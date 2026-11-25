/**
 * dsh-sensitive-guard — masks sensitive values before a model request reaches
 * the gateway, and never blocks, never aborts a turn, never throws.
 *
 * Policy (as requested):
 *   recognise → classify → replace with a placeholder → continue routing.
 *   There is no refusal branch. Every match is masked; only the log carries a
 *   risk level.
 *
 * Where it hooks:
 *
 * 1. `agent/pre-step` — masks user text as it enters a step, so the masked
 *    value is what the model reads.
 * 2. `tools/post-execute` — masks tool output before it is recorded and
 *    replayed into the next request.
 * 3. `llm/stream` — audit only. A loop-built request arrives deep-frozen, so
 *    this listener counts and logs what would still match and always delegates
 *    with `next()`.
 *
 * Invariants:
 * - Substitution is single-pass and forward-only; originals are never stored,
 *   never restored, and never logged.
 * - The session placeholder registry stores a SHA-256 digest per value, never
 *   the value itself, so the same value keeps the same placeholder across a
 *   session without the plaintext being retained anywhere.
 * - Any internal failure returns the caller's decision unchanged.
 *
 * Image handling: `@deepseek-ai/dsh-attachment-local` already strips EXIF/GPS
 * and re-encodes every admitted image, so the model never receives those
 * fields. This plugin adds OCR over the stored raster: a recognized line that
 * hits a rule is covered by an opaque fill, the result is re-encoded, stored as
 * a new attachment, and the image block is repointed at it. The original file
 * stays in the content-addressed store, which is immutable and never deleted.
 */

import { createHash } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import { probeOcr, recognizeImageWithBoxes, redactImage, readImagePixels, readFileHead, compressImage } from './ocr/runner.js';
import { readImageText, OCR_RULES, normalizeOcrText } from './ocr/normalize.js';
import { mergeBoxes, padBox } from './ocr/redact.js';
import { privacyRules, detectContainer, looksBinary, decodeQr, NAME_ID_PAIR_RULE } from './ocr/detect.js';

/** Placeholder vocabulary. */
export const PLACEHOLDERS = Object.freeze({
  secret: '{{SECRET_TOKEN}}',
  privacy: '{{PRIVACY_ID}}',
  cred: '{{CRED_CODE}}',
  path: '{{LOCAL_PATH}}',
  device: '{{DEVICE_ID}}',
  email: '{{EMAIL_ADDR}}',
  net: '{{NET_IP}}',
  url: '{{PRIVATE_URL}}',
  db: '{{DB_CRED}}',
});

/** Values that are documentation samples, not real secrets. */
const WHITELIST = ['test-key', 'demo-sk', 'example-token', 'placeholder', 'mock-secret'];

const MAX_SCAN_CHARS = 4 * 1024 * 1024;
const MAX_REGISTRY_ENTRIES = 512;

/**
 * One rule set. `risk` only decides the log line; both levels are masked.
 * Patterns are bounded so no scan is quadratic.
 */
const BASE_RULES = [
  // --- secrets: high ---
  {
    id: 'private-key',
    risk: 'high',
    to: PLACEHOLDERS.secret,
    re: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----/g,
  },
  {
    id: 'provider-token',
    risk: 'high',
    to: PLACEHOLDERS.secret,
    re: /(?<![\w-])(?:sk-|ghp_|gho_|github_pat_|glpat-|npm_|hf_|xox[baprs]-|AKIA|ASIA|LTAI|AKID|sk_live_|rk_test_|whsec_)[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: 'jwt',
    risk: 'high',
    to: PLACEHOLDERS.secret,
    re: /(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: 'bearer',
    risk: 'high',
    to: PLACEHOLDERS.secret,
    re: /((?:Authorization\s*:\s*)?Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/gi,
    keepGroup: 1,
  },
  {
    id: 'token-assignment',
    risk: 'high',
    to: PLACEHOLDERS.secret,
    re: /((?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|token|secret|storePassword|keyPassword|pkcs12(?:Password)?|signaturePassword)\s*[:=]\s*["'`]?)([A-Za-z0-9_\-./+=]{6,})/gi,
    keepGroup: 1,
  },
  // --- privacy: high ---
  {
    id: 'cn-id-card',
    risk: 'high',
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
  },
  {
    id: 'cn-mobile',
    risk: 'high',
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
  },
  {
    id: 'bank-card',
    risk: 'high',
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)\d{16,19}(?!\d)/g,
    validate: luhn,
  },
  {
    id: 'passport',
    risk: 'high',
    to: PLACEHOLDERS.privacy,
    re: /(?<![\w])(?:E\d{8}|[GH]\d{8}|[A-Z]{1,2}\d{7,8})(?![\w])/g,
  },
  // --- system credentials: high ---
  {
    id: 'service-password',
    risk: 'high',
    to: PLACEHOLDERS.cred,
    re: /((?:adb|root|ssh|server|database|db|mysql|postgres|redis|wifi|wi-fi|router)[^\n]{0,24}?(?:password|passwd|pwd|密码|口令)\s*[:=：]\s*)["'`]?[^\s"'`,;]{3,}/gi,
    keepGroup: 1,
  },
  {
    id: 'cookie-session',
    risk: 'high',
    to: PLACEHOLDERS.cred,
    re: /((?:cookie|set-cookie|session[_-]?id|jsessionid|phpsessid)\s*[:=]\s*)[^\s;,\n]{8,}/gi,
    keepGroup: 1,
  },
  {
    id: 'one-time-code',
    risk: 'high',
    to: PLACEHOLDERS.cred,
    re: /((?:验证码|短信码|2fa|otp|totp|one[- ]time(?: code| password)?)[^\n]{0,12}?[:：=\s]\s*)\d{4,8}/gi,
    keepGroup: 1,
  },
  {
    id: 'temp-login-link',
    risk: 'high',
    to: PLACEHOLDERS.cred,
    re: /\bhttps?:\/\/[^\s"'<>]{6,}?\?(?:[^\s"'<>]*?(?:token|ticket|code|sign|sig|expires|key)=)[^\s"'<>]{6,}/gi,
  },
  // --- local paths: normal ---
  {
    id: 'local-path',
    risk: 'normal',
    to: PLACEHOLDERS.path,
    re: /(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\s"'<>|,;)\]}]+|\/storage\/emulated\/\d+\/[^\s"'<>|,;)\]}]*|\/root\/[^\s"'<>|,;)\]}]*|\/home\/[^\s"'<>|,;)\]}]+|\/Users\/[^\s"'<>|,;)\]}]+)/g,
  },
  // --- device ids: normal ---
  {
    id: 'device-id',
    risk: 'normal',
    to: PLACEHOLDERS.device,
    re: /\b(?:[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{16})\b/g,
    validate: (value) => !/^\d+$/.test(value.replace(/-/g, '')),
  },
  // --- network: normal ---
  {
    id: 'net-ip',
    risk: 'normal',
    to: PLACEHOLDERS.net,
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    validate: isMaskableIp,
  },
];

/** Internal-only suffixes that mark a host as non-public. */
const INTERNAL_SUFFIXES = ['internal', 'local', 'lan', 'corp', 'intra', 'private', 'svc', 'home', 'home.arpa'];

/** Public suffixes, only masked when the caller opts into full URL masking. */
const PUBLIC_SUFFIXES = ['com', 'net', 'org', 'cn', 'io', 'dev', 'ai', 'co', 'top', 'xyz', 'me', 'app', 'site', 'cloud', 'tech'];

/**
 * Build the URL rules for one configuration.
 *
 * `maskUrls` has three levels rather than two, because masking every public
 * domain makes the model unable to read context:
 *
 * - `false` (default) — nothing.
 * - `'internal'` — hosts under an internal-only suffix only.
 * - `true` / `'all'` — every domain, including public ones.
 */
function urlRules(config) {
  const level = config.maskUrls;
  if (level === false) return [];
  const rules = [];
  const internal = config.privateUrlSuffixes ?? INTERNAL_SUFFIXES;
  rules.push({
    id: 'private-url',
    risk: 'normal',
    to: PLACEHOLDERS.url,
    re: new RegExp(`\\b(?:https?:\\/\\/)?(?:[a-z0-9-]+\\.)+(?:${internal.join('|')})\\b[A-Za-z0-9/._~:%?#@!$&'*+,;=-]*`, 'gi'),
  });
  if (level === true || level === 'all') {
    rules.push({
      id: 'domain',
      risk: 'normal',
      to: PLACEHOLDERS.url,
      re: new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${PUBLIC_SUFFIXES.join('|')})\\b`, 'gi'),
    });
  }
  return rules;
}

/** Rules only added when their option is on, most specific first. */
function optionalRules(config) {
  const rules = [];
  if (config.maskDbCredentials) {
    rules.push({
      id: 'db-credential',
      risk: 'high',
      to: PLACEHOLDERS.db,
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'<>]*/gi,
    });
  }
  rules.push({
    id: 'email',
    risk: 'normal',
    to: PLACEHOLDERS.email,
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  });
  rules.push(...urlRules(config));
  return rules;
}

function luhn(value) {
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = value.charCodeAt(index) - 48;
    if (digit < 0 || digit > 9) return false;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Loopback and broadcast addresses are not deployment secrets. */
function isMaskableIp(value) {
  return value !== '127.0.0.1' && value !== '0.0.0.0' && value !== '255.255.255.255';
}

function isWhitelisted(value, config) {
  const list = config.whitelist ?? WHITELIST;
  const lowered = value.toLowerCase();
  return list.some((token) => lowered.includes(token.toLowerCase()));
}

/**
 * Per-session placeholder registry.
 *
 * The same value always receives the same placeholder within one session. Only
 * a digest of the value is kept, so no plaintext survives in plugin memory
 * beyond the call that needed it.
 */
export function createRegistry() {
  const entries = new Map();
  const counters = new Map();
  return {
    /**
     * @param category - placeholder base text, such as `{{SECRET_TOKEN}}`.
     * @param value - the matched value; used for the digest only.
     * @returns the stable placeholder for this session.
     */
    placeholderFor(category, value) {
      const digest = createHash('sha256').update(value).digest('hex');
      const key = `${category}:${digest}`;
      const known = entries.get(key);
      if (known !== undefined) return known;
      if (entries.size >= MAX_REGISTRY_ENTRIES) return category;
      const count = (counters.get(category) ?? 0) + 1;
      counters.set(category, count);
      const placeholder = count === 1 ? category : category.replace('}}', `_${count}}}`);
      entries.set(key, placeholder);
      return placeholder;
    },
    get size() {
      return entries.size;
    },
  };
}

/** Replace one string, reporting per-placeholder counts and the worst risk. */
export function maskText(text, rules, context) {
  if (typeof text !== 'string' || text.length === 0) return { text, counts: {}, risk: undefined };
  if (text.length > MAX_SCAN_CHARS) return { text, counts: {}, risk: undefined };
  let next = text;
  const counts = {};
  let risk;
  for (const rule of rules) {
    next = next.replace(rule.re, (...args) => {
      const whole = args[0];
      if (typeof whole !== 'string') return whole;
      // Never re-match a placeholder a previous rule already wrote. Without
      // this, a later rule can swallow `{{PRIVACY_ID}}` and emit a `_2` variant
      // for a value that was already masked.
      if (whole.includes('{{')) return whole;
      if (rule.validate && !rule.validate(whole)) return whole;
      if (isWhitelisted(whole, context.config)) return whole;
      const placeholder = rule.keepGroup !== undefined
        ? context.registry.placeholderFor(rule.to, whole)
        : context.registry.placeholderFor(rule.to, whole);
      counts[placeholder] = (counts[placeholder] ?? 0) + 1;
      if (rule.risk === 'high') risk = 'high';
      else if (risk === undefined) risk = 'normal';
      return rule.keepGroup !== undefined ? `${args[rule.keepGroup]}${placeholder}` : placeholder;
    });
  }
  return { text: next, counts, risk };
}

/** Mask text blocks of a content array; other block kinds pass through. */
export function maskContent(content, rules, context) {
  if (!Array.isArray(content)) return { content, counts: {}, risk: undefined };
  let changed = false;
  const counts = {};
  let risk;
  const next = content.map((block) => {
    if (!block || block.type !== 'text' || typeof block.text !== 'string') return block;
    const masked = maskText(block.text, rules, context);
    if (masked.text === block.text) return block;
    changed = true;
    for (const [placeholder, count] of Object.entries(masked.counts)) counts[placeholder] = (counts[placeholder] ?? 0) + count;
    if (masked.risk === 'high') risk = 'high';
    else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
    return { ...block, text: masked.text };
  });
  return { content: changed ? next : content, counts, risk };
}

/** Mask string leaves of a JSON value, bounded by depth. */
export function maskValue(value, rules, context, depth = 0) {
  if (depth > 12) return { value, counts: {}, risk: undefined };
  if (typeof value === 'string') return maskText(value, rules, context);
  if (Array.isArray(value)) {
    const counts = {};
    let risk;
    let changed = false;
    const next = value.map((item) => {
      const masked = maskValue(item, rules, context, depth + 1);
      if (masked.value !== item) changed = true;
      for (const [placeholder, count] of Object.entries(masked.counts)) counts[placeholder] = (counts[placeholder] ?? 0) + count;
      if (masked.risk === 'high') risk = 'high';
      else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
      return masked.value;
    });
    return { value: changed ? next : value, counts, risk };
  }
  if (value !== null && typeof value === 'object') {
    const counts = {};
    let risk;
    let changed = false;
    const next = {};
    for (const [key, item] of Object.entries(value)) {
      const masked = maskValue(item, rules, context, depth + 1);
      if (masked.value !== item) changed = true;
      for (const [placeholder, count] of Object.entries(masked.counts)) counts[placeholder] = (counts[placeholder] ?? 0) + count;
      if (masked.risk === 'high') risk = 'high';
      else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
      next[key] = masked.value;
    }
    return { value: changed ? next : value, counts, risk };
  }
  return { value, counts: {}, risk: undefined };
}

/**
 * Audit one request that is about to be dispatched. Read-only: a loop-built
 * request is deep-frozen, so nothing here rewrites it.
 * @returns counts of values that would still match, and the worst risk.
 */
export function auditRequest(options, rules, context) {
  const counts = {};
  let risk;
  const absorb = (result) => {
    for (const [placeholder, count] of Object.entries(result.counts)) counts[placeholder] = (counts[placeholder] ?? 0) + count;
    if (result.risk === 'high') risk = 'high';
    else if (result.risk === 'normal' && risk === undefined) risk = 'normal';
  };
  if (typeof options?.system === 'string') absorb(maskText(options.system, rules, context));
  let images = 0;
  for (const message of options?.messages ?? []) {
    if (typeof message?.content === 'string') {
      absorb(maskText(message.content, rules, context));
      continue;
    }
    for (const block of message?.content ?? []) {
      if (block?.type === 'text') absorb(maskText(block.text, rules, context));
      else if (block?.type === 'tool-call') absorb(maskText(block.arguments, rules, context));
      else if (block?.type === 'image') images += 1;
    }
  }
  return { counts, risk, images };
}

/**
 * Build the ordered rule list for one resolved config.
 * @param {{maskUrls: boolean, maskDbCredentials: boolean, disabledRules: string[]}} config
 */
export function buildRules(config) {
  return [
    // The name-and-id pair must run before the plain identity-number rule, or
    // the number is replaced first and the name is left behind.
    NAME_ID_PAIR_RULE,
    ...BASE_RULES,
    ...optionalRules(config),
    ...privacyRules({
      detectAddresses: config.detectAddresses,
      detectMedical: config.detectMedical,
    }),
  ].filter((rule) => !config.disabledRules?.includes(rule.id));
}

/** Normalize the row config. */
export function resolveConfig(raw) {
  const config = raw && typeof raw === 'object' ? raw : {};
  return {
    enabled: config.enabled !== false,
    maskUserMessages: config.maskUserMessages !== false,
    maskToolResults: config.maskToolResults !== false,
    maskUrls: config.maskUrls === true || config.maskUrls === 'all' ? 'all' : config.maskUrls === 'internal' ? 'internal' : false,
    maskDbCredentials: config.maskDbCredentials !== false,
    auditRequests: config.auditRequests !== false,
    logMasks: config.logMasks !== false,
    highRiskAlertAfter: Number.isInteger(config.highRiskAlertAfter) && config.highRiskAlertAfter > 0 ? config.highRiskAlertAfter : 6,
    maxImagesPerTurn: Number.isInteger(config.maxImagesPerTurn) && config.maxImagesPerTurn > 0 ? config.maxImagesPerTurn : 3,
    disabledRules: Array.isArray(config.disabledRules) ? config.disabledRules.filter((id) => typeof id === 'string') : [],
    whitelist: Array.isArray(config.whitelist) ? config.whitelist.filter((token) => typeof token === 'string') : WHITELIST,
    ocr: config.ocr !== false,
    ocrLanguage: typeof config.ocrLanguage === 'string' && config.ocrLanguage.length > 0 ? config.ocrLanguage : 'zh-Hans-CN',
    ocrTimeoutMs: Number.isInteger(config.ocrTimeoutMs) && config.ocrTimeoutMs > 0 ? config.ocrTimeoutMs : 20000,
    ocrMaxImagesPerTurn: Number.isInteger(config.ocrMaxImagesPerTurn) && config.ocrMaxImagesPerTurn > 0 ? config.ocrMaxImagesPerTurn : 3,
    redactImages: config.redactImages !== false,
    redactColor: typeof config.redactColor === 'string' && /^#[0-9A-Fa-f]{6}$/.test(config.redactColor) ? config.redactColor : '#000000',
    detectAddresses: config.detectAddresses !== false,
    detectMedical: config.detectMedical !== false,
    detectQr: config.detectQr !== false,
    markBinary: config.markBinary !== false,
    detectBypass: config.detectBypass !== false,
    compressImages: config.compressImages !== false,
    compressMaxDimension: Number.isInteger(config.compressMaxDimension) && config.compressMaxDimension > 0 ? config.compressMaxDimension : 2048,
    imageBackend: ['auto', 'winrt', 'python', 'none'].includes(config.imageBackend) ? config.imageBackend : 'auto',
    pythonPath: typeof config.pythonPath === 'string' && config.pythonPath.length > 0 ? config.pythonPath : undefined,
    tesseractPath: typeof config.tesseractPath === 'string' && config.tesseractPath.length > 0 ? config.tesseractPath : undefined,
    tesseractLanguage: typeof config.tesseractLanguage === 'string' && config.tesseractLanguage.length > 0 ? config.tesseractLanguage : 'chi_sim+eng',
    privateUrlSuffixes: Array.isArray(config.privateUrlSuffixes) && config.privateUrlSuffixes.length > 0
      ? config.privateUrlSuffixes.filter((suffix) => typeof suffix === 'string')
      : undefined,
  };
}

export function apply(ctx, rawConfig) {
  const config = resolveConfig(rawConfig);
  if (!config.enabled) return;

  const rules = buildRules(config);
  const ocrRules = [...OCR_RULES].filter((rule) => !config.disabledRules.includes(rule.id));
  /** sessionId → registry */
  const registries = new Map();
  /** sessionId → consecutive high-risk mask count in the current turn */
  const highRiskStreaks = new Map();
  /** sessionId → Set of attachment ids already OCR-scanned */
  const scannedAttachments = new Map();

  const registryFor = (sessionId) => {
    const key = typeof sessionId === 'string' ? sessionId : 'default';
    let registry = registries.get(key);
    if (registry === undefined) {
      registry = createRegistry();
      registries.set(key, registry);
    }
    return registry;
  };

  const scannedFor = (sessionId) => {
    const key = typeof sessionId === 'string' ? sessionId : 'default';
    let seen = scannedAttachments.get(key);
    if (seen === undefined) {
      seen = new Set();
      scannedAttachments.set(key, seen);
    }
    return seen;
  };

  const log = (line) => {
    if (!config.logMasks) return;
    try {
      ctx.logger?.info?.(line);
    } catch {
      // Logging never changes a decision.
    }
  };

  /**
   * OCR availability is probed once, off the request path. Until the probe
   * settles, `ocrAvailable` stays false and images are skipped rather than
   * delaying a turn.
   */
  let ocrAvailable = false;
  if (config.ocr) {
    probeOcr({
      backend: config.imageBackend,
      pythonPath: config.pythonPath,
      tesseractPath: config.tesseractPath,
      language: config.imageBackend === 'python' ? config.tesseractLanguage : config.ocrLanguage,
      timeoutMs: config.ocrTimeoutMs,
    }).then((probe) => {
      ocrAvailable = probe.available;
      if (probe.available) {
        log(`sensitive-guard 【✅OCR就绪】backend=${probe.backend} platform=${probe.platform}`);
      } else {
        log(`sensitive-guard 【⚠️OCR不可用】${probe.reason ?? 'unknown'}（backend=${probe.backend}），图片仅做元数据清理`);
      }
    }).catch((error) => {
      ocrAvailable = false;
      log(`sensitive-guard 【⚠️OCR探测失败】${error?.message ?? 'unknown'}`);
    });
  }

  const reportMask = (sessionId, result) => {
    const summary = Object.entries(result.counts).map(([placeholder, count]) => `${placeholder}×${count}`).join(' ');
    const label = result.risk === 'high' ? '【⚠️已脱敏-高风险】' : '【⚠️已脱敏-普通】';
    log(`sensitive-guard ${label}${summary ? ` ${summary}` : ''}`);
    if (result.risk !== 'high') return;
    const streak = (highRiskStreaks.get(sessionId) ?? 0) + 1;
    highRiskStreaks.set(sessionId, streak);
    if (streak === config.highRiskAlertAfter) {
      log(`sensitive-guard 【⚠️告警】本轮已连续 ${streak} 次命中高风险脱敏，请确认上下文是否包含真实凭据`);
    }
  };

  /**
   * OCR every not-yet-scanned image of one message batch.
   *
   * Images are read through `ctx.attachments.imageHostPath()`, which is the only
   * supported way to reach a stored attachment as a file. EXIF and GPS are
   * already gone by then: `dsh-attachment-local` normalizes and re-encodes on
   * admission. What OCR adds is the text painted inside the picture.
   *
   * Never throws: a failed or unreliable read is reported and the image passes.
   */
  const ocrMessages = async (messages, sessionId, seen) => {
    const found = [];
    const unreliable = [];
    const redacted = new Map();
    let scanned = 0;
    for (const message of messages) {
      if (typeof message?.content === 'string') continue;
      for (const block of message?.content ?? []) {
        if (block?.type !== 'image') continue;
        const attachmentId = block.attachment?.attachmentId;
        if (typeof attachmentId !== 'string' || seen.has(attachmentId)) continue;
        if (scanned >= config.ocrMaxImagesPerTurn) {
          log(`sensitive-guard 【⚠️放行-OCR超限】本轮仅扫描前 ${config.ocrMaxImagesPerTurn} 张，其余图片未做 OCR`);
          return { found, unreliable, redacted, scanned };
        }
        seen.add(attachmentId);
        scanned += 1;
        let hostPath;
        try {
          hostPath = ctx.attachments?.imageHostPath?.(block.attachment);
        } catch {
          hostPath = undefined;
        }
        if (typeof hostPath !== 'string') {
          unreliable.push(attachmentId);
          log('sensitive-guard 【⚠️OCR识别不可靠】附件无宿主路径，已抹除元数据后放行');
          continue;
        }

        // A binary container is opaque: masking a chance byte sequence inside a
        // base64 blob or an archive would corrupt it without hiding anything.
        // Report the risk and leave the bytes untouched.
        if (config.markBinary) {
          try {
            const head = await readFileHead(hostPath, 16);
            const container = detectContainer(head);
            if (container !== undefined || looksBinary(head, block.attachment.name)) {
              log(`sensitive-guard 【⚠️放行-二进制内容】${container ?? 'binary'}，未解析内部`);
              seen.add(attachmentId);
              continue;
            }
          } catch {
            // A head read failure is not a reason to skip OCR.
          }
        }

        // A QR payload is a channel of its own: the code can carry a URL with a
        // token while the visible text looks clean.
        const qrPayloads = [];
        if (config.detectQr) {
          try {
            const decoded = await readImagePixels(hostPath, { timeoutMs: config.ocrTimeoutMs });
            qrPayloads.push(...(await decodeQr(decoded.pixels, decoded.width, decoded.height)));
          } catch (error) {
            log(`sensitive-guard 【⚠️二维码解析异常】${error?.message ?? 'unknown'}，继续流转`);
          }
        }

        const read = await readImageText(
          (path) => recognizeImageWithBoxes(path, { language: config.ocrLanguage, timeoutMs: config.ocrTimeoutMs }),
          hostPath,
        );
        if (!read.ok) {
          unreliable.push(attachmentId);
          log(`sensitive-guard 【⚠️OCR识别不可靠】${read.reason ?? 'unknown'}，已抹除元数据后放行`);
          continue;
        }
        if (read.unreliable.length > 0) {
          log(`sensitive-guard 【⚠️OCR识别不可靠】${read.unreliable.length} 行文本未达可信阈值，已忽略`);
        }

        // QR payloads are masked as text and reported. They cannot be edited out
        // of the pixels without covering the whole code, which would destroy it,
        // so the risk is recorded and the image passes.
        for (const payload of qrPayloads) {
          const maskedQr = maskText(payload, ocrRules, { rules: ocrRules, config, registry: registryFor(sessionId) });
          if (maskedQr.risk !== undefined) {
            log(`sensitive-guard 【⚠️二维码命中】码内含敏感内容，画内码无法就地改写，已标记风险`);
          }
        }

        // A line is redacted when any OCR rule matches it. The whole line box is
        // covered rather than the matched substring, because the engine does not
        // report per-character offsets: covering a partial line would leave a
        // readable fragment beside the fill.
        const hitLines = [];
        for (const line of read.lines) {
          const matched = ocrRules.some((rule) => {
            rule.re.lastIndex = 0;
            const hit = rule.re.test(line.text);
            rule.re.lastIndex = 0;
            return hit;
          });
          if (matched) hitLines.push(line);
          else found.push(line);
        }
        if (hitLines.length === 0) {
          // No redaction is needed, but the image still must not travel at full
          // resolution: downscale it and repoint the block.
          if (config.compressImages && Math.max(block.attachment.width, block.attachment.height) > config.compressMaxDimension) {
            const outPath = `${hostPath}.small.bin`;
            try {
              const shrunk = await compressImage(hostPath, {
                outPath,
                maxDimension: config.compressMaxDimension,
                timeoutMs: config.ocrTimeoutMs,
              });
              const saved = await ctx.attachments.saveImage({
                data: shrunk.data,
                mediaType: 'image/jpeg',
                name: block.attachment.name ?? 'compressed.jpg',
              });
              redacted.set(attachmentId, saved);
              log(`sensitive-guard 【✅已压缩】${block.attachment.width}×${block.attachment.height} → ${shrunk.width}×${shrunk.height}`);
            } catch (error) {
              log(`sensitive-guard 【⚠️压缩失败】${error?.message ?? 'unknown'}，图片保持原样`);
            } finally {
              await rm(outPath, { force: true }).catch(() => {});
            }
          }
          continue;
        }

        // Redact and store the modified copy, then point the block at it.
        if (config.redactImages) {
          const boxes = mergeBoxes(hitLines.map((line) => padBox(line, block.attachment.width, block.attachment.height)));
          const outPath = `${hostPath}.redacted.png`;
          try {
            await redactImage(hostPath, boxes, { outPath, color: config.redactColor, timeoutMs: config.ocrTimeoutMs });
            const data = await readFile(outPath, 'utf8').then(() => readFile(outPath)).catch(() => undefined);
            if (data === undefined) throw new Error('redacted-file-missing');
            const saved = await ctx.attachments.saveImage({
              data,
              mediaType: 'image/png',
              name: block.attachment.name ?? 'redacted.png',
            });
            redacted.set(attachmentId, saved);
            log(`sensitive-guard 【⚠️已涂改图片】覆盖 ${boxes.length} 个区域`);
          } catch (error) {
            log(`sensitive-guard 【⚠️涂改失败】${error?.message ?? 'unknown'}，图片保持原样`);
          } finally {
            await rm(outPath, { force: true }).catch(() => {});
          }
        }
        for (const line of hitLines) found.push(line);
      }
    }
    return { found, unreliable, redacted, scanned };
  };

  // 1. Mask user text as it enters a step. Never rejects, never throws.
  ctx.on('agent/pre-step', async ({ agent, messages }, next) => {
    const decision = await next();
    try {
      const sessionId = agent?.id;
      if (Array.isArray(messages) && messages.some((message) => message?.source?.kind === 'user')) {
        highRiskStreaks.delete(sessionId);
      }
      if (!config.maskUserMessages) return decision;
      if (decision?.kind !== 'enter' || !Array.isArray(decision.messages)) return decision;
      const context = { rules, config, registry: registryFor(sessionId) };
      const totals = { counts: {}, risk: undefined };
      let changed = false;
      const maskedMessages = decision.messages.map((message) => {
        if (typeof message?.content === 'string') {
          const masked = maskText(message.content, rules, context);
          if (masked.text === message.content) return message;
          changed = true;
          for (const [placeholder, count] of Object.entries(masked.counts)) totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
          if (masked.risk === 'high') totals.risk = 'high';
          else if (masked.risk === 'normal' && totals.risk === undefined) totals.risk = 'normal';
          return { ...message, content: masked.text };
        }
        const masked = maskContent(message?.content, rules, context);
        if (masked.content === message?.content) return message;
        changed = true;
        for (const [placeholder, count] of Object.entries(masked.counts)) totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
        if (masked.risk === 'high') totals.risk = 'high';
        else if (masked.risk === 'normal' && totals.risk === undefined) totals.risk = 'normal';
        return { ...message, content: masked.content };
      });

      // OCR the pictures in this step. A line that hits an OCR rule is covered
      // by an opaque fill and the block is repointed at the redacted copy, so the
      // model receives the covered raster rather than the original pixels.
      let finalMessages = maskedMessages;
      if (config.ocr && ocrAvailable) {
        const seen = scannedFor(sessionId);
        const ocr = await ocrMessages(decision.messages, sessionId, seen);
        if (ocr.found.length > 0) {
          const ocrContext = { rules: ocrRules, config, registry: registryFor(sessionId) };
          for (const line of ocr.found) {
            const masked = maskText(line.text, ocrRules, ocrContext);
            for (const [placeholder, count] of Object.entries(masked.counts)) totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
            if (masked.risk === 'high') totals.risk = 'high';
            else if (masked.risk === 'normal' && totals.risk === undefined) totals.risk = 'normal';
          }
        }
        if (ocr.redacted.size > 0) {
          changed = true;
          finalMessages = maskedMessages.map((message) => {
            if (typeof message?.content === 'string') return message;
            let touched = false;
            const content = (message?.content ?? []).map((block) => {
              if (block?.type !== 'image') return block;
              const replacement = ocr.redacted.get(block.attachment?.attachmentId);
              if (replacement === undefined) return block;
              touched = true;
              return { ...block, attachment: replacement };
            });
            return touched ? { ...message, content } : message;
          });
        }
      }

      if (!changed && totals.risk === undefined) {
        log('sensitive-guard 【✅无敏感】');
        return decision;
      }
      if (Object.keys(totals.counts).length > 0) reportMask(sessionId, totals);
      else if (totals.risk !== undefined) log(`sensitive-guard ${totals.risk === 'high' ? '【⚠️已脱敏-高风险】' : '【⚠️已脱敏-普通】'} 图片已涂改`);
      return changed ? { ...decision, messages: finalMessages } : decision;
    } catch {
      return decision;
    }
  });

  // 2. Mask tool output before it is recorded and replayed.
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next();
    try {
      if (!config.maskToolResults) return decision;
      if (decision?.kind !== 'accept') return decision;
      const sessionId = exec?.agent?.id;
      const context = { rules, config, registry: registryFor(sessionId) };
      const totals = { counts: {}, risk: undefined };
      let changed = false;
      let nextDecision = decision;
      if (Array.isArray(decision.content)) {
        const masked = maskContent(decision.content, rules, context);
        if (masked.content !== decision.content) {
          changed = true;
          Object.assign(totals.counts, masked.counts);
          totals.risk = masked.risk;
          nextDecision = { ...nextDecision, content: masked.content };
        }
      }
      if (decision.value !== undefined && nextDecision.content === undefined) {
        const masked = maskValue(decision.value, rules, context);
        if (masked.value !== decision.value) {
          changed = true;
          Object.assign(totals.counts, masked.counts);
          totals.risk = masked.risk;
          nextDecision = { ...nextDecision, value: masked.value };
        }
      }
      if (!changed) return decision;
      reportMask(sessionId, totals);
      return nextDecision;
    } catch {
      return decision;
    }
  });

  // 3. Audit the dispatched request. Read-only; always delegates.
  ctx.on('llm/stream', (options, next) => {
    try {
      if (!config.auditRequests) return next();

      // A request with no session id was not built by the agent loop for a
      // session this guard observes: a direct call that bypassed the normal
      // path. It is still audited, and the bypass is recorded.
      if (config.detectBypass && options?.sessionId === undefined) {
        log('sensitive-guard 【⚠️旁路风险】检测到无会话归属的直连请求，仍执行脱敏审计');
      }

      const verdict = auditRequest(options, rules, { rules, config, registry: registryFor(options?.sessionId) });
      if (verdict.risk !== undefined) {
        const summary = Object.entries(verdict.counts).map(([placeholder, count]) => `${placeholder}×${count}`).join(' ');
        log(`sensitive-guard 【⚠️放行-脱敏未覆盖】${summary}（请求体已冻结，未改写）`);
      }
      if (verdict.images > config.maxImagesPerTurn) {
        log(`sensitive-guard 【⚠️放行-图片超限】本轮 ${verdict.images} 张，上限 ${config.maxImagesPerTurn}，建议分批`);
      }
    } catch {
      // Audit failure must not affect dispatch.
    }
    return next();
  });
}

export default apply;