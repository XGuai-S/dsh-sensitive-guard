/**
 * dsh-sensitive-guard — 敏感内容拦截与脱敏 Skill（pre-step 钩子专用）。
 *
 * 三级分类 / Three levels:
 *
 * - **BLOCK** 阻断：命中即拦截，不写 session、不转发模型。私钥、身份、支付、
 *   高权限密码、联系方式、验证码、详细住址、绕过攻击指令。
 * - **MASK** 脱敏：替换为占位符后正常写入。网络、设备、会话、交易、证书、
 *   路径、指纹。
 * - **PASS** 放行：白名单与无敏感内容，原文写入。
 *
 * 挂载点 / Hook points:
 *
 * 1. `agent/pre-step` — 白名单 > 绕过判定 > BLOCK > MASK > PASS。
 * 2. `tools/post-execute` — 工具与子代理输出入库前二次分级。
 * 3. `llm/stream` — 请求侧审计 + 响应侧流式扫描。
 *
 * 关于 inbox / About the inbox:
 *
 * DSH 在 API 层 `agent.followup()` 就把用户输入写入 inbox，`agent/pre-step`
 * 在此之后才触发。因此插件**无法**阻止明文进入 inbox；它能保证的是
 * session 不含明文、请求不含明文。BLOCK 的真实效果是「不写 session、
 * 不转发模型」，inbox 中的明文需要事后清理（`cleanupInbox` 开关）。
 *
 * DSH writes the user prompt into the inbox inside the API layer, before
 * `agent/pre-step` runs. This plugin therefore cannot keep plaintext out of the
 * inbox; it guarantees the session and the request carry no plaintext. A BLOCK
 * means "no session write, no model call".
 */

import { readFile, rm } from 'node:fs/promises';
import { probeOcr, recognizeImageWithBoxes, redactImage, readImagePixels, readFileHead, compressImage } from './ocr/runner.js';
import { readImageText, OCR_RULES } from './ocr/normalize.js';
import { mergeBoxes, padBox } from './ocr/redact.js';
import { privacyRules, detectContainer, looksBinary, decodeQr, NAME_ID_PAIR_RULE } from './ocr/detect.js';
import { maskResponseStream, maskBase64Payloads } from './response.js';
import { interceptPayload, interceptPromptBody, replaceRequestBody, isPromptEnvelope, isPromptEndpoint, sanitizeArgs } from './prebody.js';
import { detectBypassAttempt, userTextOf, BYPASS_KIND } from './bypass.js';
import {
  PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, HIGH_RISK_KINDS, LEVELS,
  buildRules, luhn, isExcluded, isHighEntropy, validateBankCard, shannonEntropy,
  CHUNK_SIZE, MAX_RECURSE_DEPTH,
} from './rules.js';
import {
  createRegistry, isWhitelistedValue, scanText, scanDeep, scanValue, scanContent,
  runSanitize, auditRequest, structuredLog, maskPreview, inputHash, chunkText,
} from './masking.js';

export {
  PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, HIGH_RISK_KINDS, LEVELS,
  buildRules, luhn, isExcluded, isHighEntropy, validateBankCard, shannonEntropy,
  CHUNK_SIZE, MAX_RECURSE_DEPTH,
};
export {
  createRegistry, isWhitelistedValue, scanText, scanDeep, scanValue, scanContent,
  runSanitize, auditRequest, structuredLog, maskPreview, inputHash, chunkText,
};
export { maskResponseStream, maskBase64Payloads, privacyRules, NAME_ID_PAIR_RULE };
export { interceptPayload, interceptPromptBody, replaceRequestBody, isPromptEnvelope, isPromptEndpoint, sanitizeArgs };
export { detectBypassAttempt, userTextOf, BYPASS_KIND };

/** 拦截提示 / Refusal notice. */
export const BLOCK_NOTICE = '【阻断拦截】检测到阻断类敏感内容，不写入 session';

/** 绕过攻击提示 / Bypass notice. */
export const BYPASS_NOTICE = '【检测到绕过脱敏的指令，已拦截并上报】';

/**
 * 构建含隐私规则的完整规则表 / Build the full rule table with privacy rules.
 *
 * 住址、病历、姓名+证件规则来自 OCR 层，在这里注入，避免 `rules.js`
 * 反向依赖造成循环引用。
 */
export function buildFullRules(config) {
  const extra = [];
  if (config.detectAddresses || config.detectMedical) {
    extra.push(...privacyRules({
      detectAddresses: config.detectAddresses,
      detectMedical: config.detectMedical,
    }));
  }
  // 「姓名+证件」必须最先跑，否则证件号先被替换，姓名留在原地。
  extra.unshift(NAME_ID_PAIR_RULE);
  return buildRules(config, extra);
}

/**
 * 归一化配置 / Normalize the row config.
 * @param {unknown} raw
 */
export function resolveConfig(raw) {
  const config = raw && typeof raw === 'object' ? raw : {};
  return {
    // --- 调试开关 / debug switches ---
    enabled: config.enabled !== false,
    // 全局旁路：跳过全部检测，仅用于调试。生产环境必须为 false。
    bypassSanitize: config.bypassSanitize === true,
    // 混合文本模式：关闭=整段阻断，开启=只清除敏感片段。
    partialBlock: config.partialBlock === true,
    // HTTP 层前置拦截：在明文进入 inbox 之前改写请求体。
    // 这是唯一能阻止明文进 inbox 的位置；默认开启，失败即放行。
    interceptPromptBody: config.interceptPromptBody !== false,
    // 诊断开关：记录每个到达 connection/request 的请求，用于确认传输通道。
    diagnoseTransport: config.diagnoseTransport === true,

    // --- 模式 / mode ---
    blockOnRisk: config.blockOnRisk === 'normal' ? 'normal' : 'high',
    blockBypass: config.blockBypass !== false,

    // --- 挂载点开关 / hook switches ---
    maskUserMessages: config.maskUserMessages !== false,
    maskToolResults: config.maskToolResults !== false,
    maskResponses: config.maskResponses !== false,
    maskSubagentReturns: config.maskSubagentReturns !== false,
    auditRequests: config.auditRequests !== false,

    // --- 规则开关 / rule switches ---
    maskUrls: config.maskUrls === true || config.maskUrls === 'all' ? 'all' : config.maskUrls === 'internal' ? 'internal' : false,
    privateUrlSuffixes: Array.isArray(config.privateUrlSuffixes) && config.privateUrlSuffixes.length > 0
      ? config.privateUrlSuffixes.filter((suffix) => typeof suffix === 'string')
      : undefined,
    maskDbCredentials: config.maskDbCredentials !== false,
    maskPublicKeys: config.maskPublicKeys === true,
    detectHighEntropy: config.detectHighEntropy !== false,
    detectAddresses: config.detectAddresses !== false,
    detectMedical: config.detectMedical !== false,
    detectQr: config.detectQr !== false,
    detectBase64: config.detectBase64 === true,
    detectBypass: config.detectBypass !== false,
    markBinary: config.markBinary !== false,
    disabledRules: Array.isArray(config.disabledRules) ? config.disabledRules.filter((id) => typeof id === 'string') : [],
    whitelist: Array.isArray(config.whitelist) ? config.whitelist.filter((token) => typeof token === 'string') : DEFAULT_WHITELIST,
    globalWhitelist: Array.isArray(config.globalWhitelist) ? config.globalWhitelist.filter((token) => typeof token === 'string') : [],
    sessionWhitelist: Array.isArray(config.sessionWhitelist) ? config.sessionWhitelist.filter((token) => typeof token === 'string') : [],

    // --- 日志与告警 / logging and alerts ---
    logMasks: config.logMasks !== false,
    logToStderr: config.logToStderr !== false,
    logFormat: config.logFormat === 'text' ? 'text' : 'json',
    highRiskAlertAfter: Number.isInteger(config.highRiskAlertAfter) && config.highRiskAlertAfter > 0 ? config.highRiskAlertAfter : 6,
    perSessionStats: config.perSessionStats !== false,

    // --- 图片 / images ---
    maxImagesPerTurn: Number.isInteger(config.maxImagesPerTurn) && config.maxImagesPerTurn > 0 ? config.maxImagesPerTurn : 3,
    ocr: config.ocr !== false,
    // 本地 OCR 或上游 OCR。上游模式会把原图外传，需要显式开启。
    ocrMode: config.ocrMode === 'upstream' ? 'upstream' : 'local',
    imageBackend: ['auto', 'winrt', 'python', 'none'].includes(config.imageBackend) ? config.imageBackend : 'auto',
    pythonPath: typeof config.pythonPath === 'string' && config.pythonPath.length > 0 ? config.pythonPath : undefined,
    tesseractPath: typeof config.tesseractPath === 'string' && config.tesseractPath.length > 0 ? config.tesseractPath : undefined,
    ocrLanguage: typeof config.ocrLanguage === 'string' && config.ocrLanguage.length > 0 ? config.ocrLanguage : 'zh-Hans-CN',
    tesseractLanguage: typeof config.tesseractLanguage === 'string' && config.tesseractLanguage.length > 0 ? config.tesseractLanguage : 'chi_sim+eng',
    ocrTimeoutMs: Number.isInteger(config.ocrTimeoutMs) && config.ocrTimeoutMs > 0 ? config.ocrTimeoutMs : 20000,
    ocrMaxImagesPerTurn: Number.isInteger(config.ocrMaxImagesPerTurn) && config.ocrMaxImagesPerTurn > 0 ? config.ocrMaxImagesPerTurn : 3,
    redactImages: config.redactImages !== false,
    redactColor: typeof config.redactColor === 'string' && /^#[0-9A-Fa-f]{6}$/.test(config.redactColor) ? config.redactColor : '#000000',
    compressImages: config.compressImages !== false,
    compressMaxDimension: Number.isInteger(config.compressMaxDimension) && config.compressMaxDimension > 0 ? config.compressMaxDimension : 2048,
  };
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {unknown} rawConfig
 */
export function apply(ctx, rawConfig) {
  const config = resolveConfig(rawConfig);
  if (!config.enabled) return;

  // 全局永久白名单并入配置白名单。
  if (config.globalWhitelist.length > 0) {
    config.whitelist = [...new Set([...config.whitelist, ...config.globalWhitelist])];
  }

  const rules = buildFullRules(config);
  const ocrRules = [...OCR_RULES].filter((rule) => !config.disabledRules.includes(rule.id));

  /** sessionId → 占位符注册表 */
  const registries = new Map();
  /** sessionId → 连续高风险计数 */
  const highRiskStreaks = new Map();
  /** sessionId → 已分析的附件 */
  const scannedAttachments = new Map();
  /** sessionId → 会话临时白名单 */
  const sessionWhitelists = new Map();

  const keyOf = (sessionId) => (typeof sessionId === 'string' ? sessionId : 'default');

  const registryFor = (sessionId) => {
    const key = keyOf(sessionId);
    let registry = registries.get(key);
    if (registry === undefined) {
      registry = createRegistry();
      registries.set(key, registry);
    }
    return registry;
  };

  const scannedFor = (sessionId) => {
    const key = keyOf(sessionId);
    let seen = scannedAttachments.get(key);
    if (seen === undefined) {
      seen = new Set();
      scannedAttachments.set(key, seen);
    }
    return seen;
  };

  const whitelistFor = (sessionId) => {
    const key = keyOf(sessionId);
    let list = sessionWhitelists.get(key);
    if (list === undefined) {
      list = new Set(config.sessionWhitelist);
      sessionWhitelists.set(key, list);
    }
    return list;
  };

  const contextFor = (sessionId) => ({
    rules,
    config,
    registry: registryFor(sessionId),
    sessionWhitelist: whitelistFor(sessionId),
  });

  /**
   * 输出一条日志 / Emit one log line.
   *
   * 同时写 stderr：`ctx.logger` 在某些部署下被吞掉，诊断期间需要一条能直接
   * 看到的通道。`logToStderr` 可关闭。
   *
   * Also writes to stderr: `ctx.logger` is swallowed in some deployments, and
   * diagnostics need a channel that is visibly present.
   */
  const log = (line) => {
    if (!config.logMasks) return;
    try {
      ctx.logger?.info?.(line);
    } catch {
      // 日志失败不得改变判定。
    }
    if (config.logToStderr !== false) {
      try {
        process.stderr.write(`${line}\n`);
      } catch {
        // 忽略。
      }
    }
  };

  /**
   * 输出一条结构化日志 / Emit one structured log line.
   *
   * 规格固定字段 time/source/level/hitType/hitText/ruleId/inputHash。
   * `hitText` 只含掩码预览，不含原文。
   */
  const report = (result, source, rawText) => {
    const digest = inputHash(rawText);
    if (config.logFormat === 'json') {
      log(`sensitive-guard ${structuredLog(result, source, digest)}`);
    } else {
      const kinds = result.kinds?.size > 0 ? [...result.kinds].join('/') : '-';
      const counts = Object.entries(result.counts ?? {}).map(([p, c]) => `${p}×${c}`).join(' ');
      log(`sensitive-guard [${source}] level=${result.level} 命中=${kinds}${counts ? ` ${counts}` : ''} hash=${digest}`);
    }

    if (result.level !== LEVELS.block) return;
    const key = keyOf(source);
    const streak = (highRiskStreaks.get(key) ?? 0) + 1;
    highRiskStreaks.set(key, streak);
    if (streak === config.highRiskAlertAfter) {
      log(`sensitive-guard 【⚠️告警】本会话已连续 ${streak} 次命中阻断级内容，请确认上下文是否包含真实凭据`);
    }
  };

  // ==================== OCR 可用性探测 ====================
  let ocrAvailable = false;
  if (config.ocr) {
    if (config.ocrMode === 'upstream') {
      log('sensitive-guard 【⚠️风险提示】OCR 为上游模式，原图会外传至外部服务');
    }
    probeOcr({
      backend: config.imageBackend,
      pythonPath: config.pythonPath,
      tesseractPath: config.tesseractPath,
      language: config.imageBackend === 'python' ? config.tesseractLanguage : config.ocrLanguage,
      timeoutMs: config.ocrTimeoutMs,
    }).then((probe) => {
      ocrAvailable = probe.available;
      if (probe.available) {
        log(`sensitive-guard 【✅OCR就绪】backend=${probe.backend} mode=${config.ocrMode} platform=${probe.platform}`);
      } else {
        log(`sensitive-guard 【⚠️OCR不可用】${probe.reason ?? 'unknown'}（backend=${probe.backend}），图片仅做元数据清理`);
      }
    }).catch((error) => {
      ocrAvailable = false;
      log(`sensitive-guard 【⚠️OCR探测失败】${error?.message ?? 'unknown'}`);
    });
  }

  // ==================== 图片分析 ====================
  const analyzeImages = async (messages, sessionId) => {
    const found = [];
    const unreliable = [];
    const replacements = new Map();
    const seen = scannedFor(sessionId);
    const whitelist = whitelistFor(sessionId);
    let scanned = 0;

    for (const message of messages) {
      if (typeof message?.content === 'string') continue;
      for (const block of message?.content ?? []) {
        if (block?.type !== 'image') continue;
        const attachmentId = block.attachment?.attachmentId;
        if (typeof attachmentId !== 'string' || seen.has(attachmentId)) continue;

        if (scanned >= config.ocrMaxImagesPerTurn) {
          log(`sensitive-guard 【⚠️放行-OCR超限】本轮仅分析前 ${config.ocrMaxImagesPerTurn} 张`);
          return { found, unreliable, replacements, scanned };
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

        // 二进制与压缩包不解析内部，只标记放行。
        if (config.markBinary) {
          try {
            const head = await readFileHead(hostPath, 16);
            const container = detectContainer(head);
            if (container !== undefined || looksBinary(head, block.attachment.name)) {
              log(`sensitive-guard 【⚠️放行-二进制内容】${container ?? 'binary'}，未解析内部`);
              continue;
            }
          } catch {
            // 读取失败不构成跳过 OCR 的理由。
          }
        }

        // 二维码：码内内容独立于画面文字。
        if (config.detectQr) {
          try {
            const decoded = await readImagePixels(hostPath, { timeoutMs: config.ocrTimeoutMs });
            for (const payload of await decodeQr(decoded.pixels, decoded.width, decoded.height)) {
              const scannedQr = scanText(payload, ocrRules, { rules: ocrRules, config, registry: registryFor(sessionId), sessionWhitelist: whitelist });
              if (scannedQr.level !== LEVELS.pass) {
                log(`sensitive-guard 【⚠️二维码命中】level=${scannedQr.level}，画内码无法就地改写，已标记风险`);
              }
            }
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
          log(`sensitive-guard 【⚠️OCR识别不可靠】${read.unreliable.length} 行未达可信阈值，已忽略`);
        }

        // 命中行整行涂改：引擎不返回字符级偏移，只涂子串会留下可读碎片。
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
          if (config.compressImages && Math.max(block.attachment.width, block.attachment.height) > config.compressMaxDimension) {
            const outPath = `${hostPath}.small.bin`;
            try {
              const shrunk = await compressImage(hostPath, { outPath, maxDimension: config.compressMaxDimension, timeoutMs: config.ocrTimeoutMs });
              const saved = await ctx.attachments.saveImage({ data: shrunk.data, mediaType: 'image/jpeg', name: block.attachment.name ?? 'compressed.jpg' });
              replacements.set(attachmentId, saved);
              log(`sensitive-guard 【✅已压缩】${block.attachment.width}×${block.attachment.height} → ${shrunk.width}×${shrunk.height}`);
            } catch (error) {
              log(`sensitive-guard 【⚠️压缩失败】${error?.message ?? 'unknown'}，图片保持原样`);
            } finally {
              await rm(outPath, { force: true }).catch(() => {});
            }
          }
          continue;
        }

        if (config.redactImages) {
          const boxes = mergeBoxes(hitLines.map((line) => padBox(line, block.attachment.width, block.attachment.height)));
          const outPath = `${hostPath}.redacted.png`;
          try {
            await redactImage(hostPath, boxes, { outPath, color: config.redactColor, timeoutMs: config.ocrTimeoutMs });
            const data = await readFile(outPath).catch(() => undefined);
            if (data === undefined) throw new Error('redacted-file-missing');
            const saved = await ctx.attachments.saveImage({ data, mediaType: 'image/png', name: block.attachment.name ?? 'redacted.png' });
            replacements.set(attachmentId, saved);
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
    return { found, unreliable, replacements, scanned };
  };

  // ==================== 0. HTTP 前置拦截（早于 inbox） ====================
  /**
   * 在 RPC 层改写 `session/prompt` 的 payload，使明文不进入 inbox。
   *
   * 为什么包装 `dispatchRpc` 而不是注册 interceptor：
   *
   * `/api` 通道已被 `typertGateway` 注册为唯一 interceptor，
   * `ctx.connection.rpc.intercept` 对同一通道会抛
   * "already has an interceptor"。因此改为包装 Gateway 自己的
   * `dispatchRpc`：它正是那个 interceptor 转发的目标，位置等价，
   * 且不改动已有注册。
   *
   * Why wrap `dispatchRpc` instead of registering an interceptor: the `/api`
   * channel already belongs to `typertGateway`, and a second registration
   * throws "already has an interceptor". Wrapping the gateway's own
   * `dispatchRpc` reaches the same point without touching that registration.
   *
   * 用 `ctx.inject` 等待服务就绪：`apply()` 执行时 `typertGateway` 可能尚未
   * 挂载，直接 `ctx.get()` 会拿到 undefined，包装就静默失效。
   *
   * `ctx.inject` waits for the service: at `apply()` time the gateway may not be
   * mounted yet, and a bare `ctx.get()` would silently skip the wrapper.
   *
   * 失败即放行：任何异常都调用原方法继续。
   */
  if (config.interceptPromptBody) {
    ctx.inject(['typertGateway'], (gatewayCtx) => {
      const gateway = gatewayCtx.typertGateway;
      if (gateway === undefined || typeof gateway.dispatchRpc !== 'function') {
        log('sensitive-guard 【⚠️RPC前置拦截不可用】typertGateway.dispatchRpc 不存在，仅依赖 pre-step');
        return;
      }
      const original = gateway.dispatchRpc;
      gateway.dispatchRpc = async function patchedDispatchRpc(endpoint, payload, signal, peer) {
        if (config.bypassSanitize) return original.call(this, endpoint, payload, signal, peer);
        try {
          const outcome = interceptPayload(endpoint, payload, rules, contextFor, log, {
            diagnose: config.diagnoseTransport === true,
          });
          const nextPayload = outcome.handled ? outcome.payload : payload;
          return await original.call(this, endpoint, nextPayload, signal, peer);
        } catch (error) {
          log(`sensitive-guard 【⚠️RPC前置拦截异常】${error?.message ?? 'unknown'}，原样放行`);
          return original.call(this, endpoint, payload, signal, peer);
        }
      };
      gatewayCtx.effect(() => () => {
        // 卸载时还原原方法，避免 HMR 叠加多层包装。
        gateway.dispatchRpc = original;
      }, 'sensitive-guard: dispatchRpc wrapper');
      log('sensitive-guard 【✅RPC前置拦截已启用】包装 typertGateway.dispatchRpc，覆盖 inbox 前置清洗');
    });
  }

  /**
   * HTTP 层兜底（真实 HTTP 部署时生效）。
   *
   * 与上面的 RPC interceptor 互补：进程内 fetch 走 interceptor，真实 HTTP
   * 请求两条都会经过。
   *
   * Complements the RPC interceptor: in-process fetch uses the interceptor,
   * real HTTP traffic passes both.
   */
  ctx.on('connection/request', async (request, _response, next) => {
    try {
      if (config.bypassSanitize || !config.interceptPromptBody) return next();

      const outcome = await interceptPromptBody(request, rules, contextFor, log, {
        diagnose: config.diagnoseTransport === true,
      });
      if (outcome.replay !== undefined) {
        // 原地改写请求体：bridge 持有 req 引用，只能改它自身的迭代器。
        replaceRequestBody(request, outcome.replay);
      }
      return next();
    } catch (error) {
      log(`sensitive-guard 【⚠️HTTP前置拦截异常】${error?.message ?? 'unknown'}，原样放行`);
      return next();
    }
  });

  // ==================== 1. pre-step：三级分支 ====================
  ctx.on('agent/pre-step', async ({ agent, messages }, next) => {
    const decision = await next();
    const sessionId = agent?.id;
    try {
      // 调试旁路：跳过全部检测，原文写入。
      if (config.bypassSanitize) {
        log('sensitive-guard 【⚠️调试旁路已开启】跳过全部敏感检测，生产环境请关闭');
        return decision;
      }

      if (Array.isArray(messages) && messages.some((message) => message?.source?.kind === 'user')) {
        highRiskStreaks.delete(keyOf(sessionId));
      }
      if (!config.maskUserMessages) return decision;
      if (decision?.kind !== 'enter' || !Array.isArray(decision.messages)) return decision;

      // 绕过判定优先于脱敏：命中即拦截。
      if (config.detectBypass && config.blockBypass) {
        for (const message of decision.messages) {
          if (message?.source?.kind !== 'user') continue;
          const text = userTextOf(message.content);
          const verdict = detectBypassAttempt(text);
          if (verdict.bypass) {
            log(`sensitive-guard ${structuredLog({ level: LEVELS.block, kinds: new Set([BYPASS_KIND]), hits: [{ ruleId: verdict.rule, kind: BYPASS_KIND, level: LEVELS.block }], counts: {} }, 'user_input', inputHash(text))}`);
            log(`sensitive-guard 【⛔绕过攻击尝试】rule=${verdict.rule} 已拦截，不写 session、不转发模型`);
            return { kind: 'reject' };
          }
        }
      }

      const context = contextFor(sessionId);
      let level = LEVELS.pass;
      let changed = false;
      const totals = { counts: {}, kinds: new Set(), hits: [] };
      const absorb = (result) => {
        for (const [placeholder, count] of Object.entries(result.counts ?? {})) {
          totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
        }
        for (const kind of result.kinds ?? []) totals.kinds.add(kind);
        totals.hits.push(...(result.hits ?? []));
        if (result.level === LEVELS.block) level = LEVELS.block;
        else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
      };

      // 逐消息分级扫描。
      const maskedMessages = decision.messages.map((message) => {
        if (typeof message?.content === 'string') {
          const result = runSanitize(message.content, rules, context);
          absorb(result);
          if (result.content === message.content) return message;
          changed = true;
          return { ...message, content: result.content };
        }
        const result = scanContent(message?.content, rules, context);
        absorb(result);
        if (result.content === message?.content) return message;
        changed = true;
        return { ...message, content: result.content };
      });

      // 图片分析：OCR 文本走同一套分级规则，命中行涂改。
      let finalMessages = maskedMessages;
      if (config.ocr && ocrAvailable) {
        const analysis = await analyzeImages(decision.messages, sessionId);
        if (analysis.found.length > 0) {
          for (const line of analysis.found) {
            absorb(runSanitize(line.text, ocrRules, context));
          }
          log(`sensitive-guard 【⚠️OCR命中】图片内含敏感文字 ${analysis.found.length} 行`);
        }
        if (analysis.replacements.size > 0) {
          finalMessages = finalMessages.map((message) => {
            if (typeof message?.content === 'string' || !Array.isArray(message?.content)) return message;
            let touched = false;
            const content = message.content.map((block) => {
              if (block?.type !== 'image') return block;
              const replacement = analysis.replacements.get(block.attachment?.attachmentId);
              if (replacement === undefined) return block;
              touched = true;
              return { ...block, attachment: replacement };
            });
            return touched ? { ...message, content } : message;
          });
          changed = true;
        }
      }

      // BLOCK：清洗后继续，不阻断任务。
      //
      // 规格明确要求「只清洗、不阻断、不中断对话」：命中阻断级内容时，
      // 敏感片段已被占位符替换，清洗后的文本正常写入 session 并转发模型。
      // 这与「拦截整条消息」是两种策略，此处采用前者。
      //
      // The spec requires cleaning, never blocking: sensitive spans are already
      // replaced, and the cleaned text goes on to the session and the model.
      if (level === LEVELS.block) {
        report({ ...totals, level }, 'user_input', JSON.stringify(totals.counts));
        log(`sensitive-guard 【🧹自动清洗】已剔除敏感片段 命中=${[...totals.kinds].join('/') || '其他'}，任务继续`);
        return { ...decision, messages: finalMessages };
      }

      if (level === LEVELS.mask) {
        report({ ...totals, level }, 'user_input', JSON.stringify(totals.counts));
        return { ...decision, messages: finalMessages };
      }

      log(`sensitive-guard [user_input] level=PASS 无敏感内容`);
      return decision;
    } catch (error) {
      // 扫描异常：标记 ERROR 并放行，不阻断任务。
      log(`sensitive-guard 【扫描异常】${error?.message ?? 'unknown'}，已放行原决策`);
      return decision;
    }
  });

  // ==================== 2. post-execute：工具与子代理输出 ====================
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next();
    const sessionId = exec?.agent?.id;
    try {
      if (config.bypassSanitize) return decision;
      if (!config.maskToolResults) return decision;
      if (decision?.kind !== 'accept') return decision;

      const context = contextFor(sessionId);
      const totals = { counts: {}, kinds: new Set(), hits: [] };
      let level = LEVELS.pass;
      let changed = false;
      let nextDecision = decision;

      const absorb = (result) => {
        for (const [placeholder, count] of Object.entries(result.counts ?? {})) {
          totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
        }
        for (const kind of result.kinds ?? []) totals.kinds.add(kind);
        totals.hits.push(...(result.hits ?? []));
        if (result.level === LEVELS.block) level = LEVELS.block;
        else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
      };

      if (Array.isArray(decision.content)) {
        const result = scanContent(decision.content, rules, context);
        absorb(result);
        if (result.content !== decision.content) {
          changed = true;
          nextDecision = { ...nextDecision, content: result.content };
        }
      }
      if (decision.value !== undefined && nextDecision.content === undefined) {
        const result = scanValue(decision.value, rules, context);
        absorb(result);
        if (result.value !== decision.value) {
          changed = true;
          nextDecision = { ...nextDecision, value: result.value };
        }
      }

      // 工具输出同样只清洗、不阻断：清洗后的结果正常写入。
      if (level === LEVELS.block) {
        report({ ...totals, level }, 'tool_result', JSON.stringify(totals.counts));
        log(`sensitive-guard 【🧹工具输出清洗】已剔除敏感片段 命中=${[...totals.kinds].join('/') || '其他'}，继续流转`);
        return nextDecision;
      }
      if (level === LEVELS.mask) {
        report({ ...totals, level }, 'tool_result', JSON.stringify(totals.counts));
        return nextDecision;
      }
      if (changed) return nextDecision;
      return decision;
    } catch (error) {
      log(`sensitive-guard 【扫描异常】${error?.message ?? 'unknown'}，已放行工具结果`);
      return decision;
    }
  });

  // ==================== 3. llm/stream：请求审计 + 响应扫描 ====================
  ctx.on('llm/stream', (options, next) => {
    const sessionId = options?.sessionId;
    try {
      if (config.bypassSanitize) {
        log('sensitive-guard 【⚠️调试旁路已开启】跳过全部敏感检测');
        return next();
      }

      // 旁路检测：没有会话归属的请求不是 Agent 循环构建的。
      if (config.detectBypass && sessionId === undefined) {
        log('sensitive-guard 【⚠️旁路风险】检测到无会话归属的直连请求，仍执行扫描');
      }

      if (config.auditRequests) {
        const verdict = auditRequest(options, rules, contextFor(sessionId));
        if (verdict.level === LEVELS.block) {
          // 请求体已深冻结，插件无法改写；此处只告警，不阻断请求。
          // 真正的清洗发生在 agent/pre-step，那里已经处理过用户输入。
          //
          // A loop-built request is deep-frozen and cannot be rewritten here.
          // Cleaning already happened at agent/pre-step; this only reports.
          report({ ...verdict, level: LEVELS.block }, 'request_audit', JSON.stringify(verdict.counts));
          log('sensitive-guard 【⚠️请求侧残余】命中阻断级内容但请求体已冻结，无法改写，已告警');
        } else if (verdict.level === LEVELS.mask) {
          report({ ...verdict, level: LEVELS.mask }, 'request_audit', JSON.stringify(verdict.counts));
          log('sensitive-guard 【⚠️请求侧残余】请求体已冻结，未改写，仅告警');
        }
        if (verdict.images > config.maxImagesPerTurn) {
          log(`sensitive-guard 【⚠️放行-图片超限】本轮 ${verdict.images} 张，上限 ${config.maxImagesPerTurn}`);
        }
      }

      const downstream = next();
      if (!config.maskResponses) return downstream;

      return maskResponseStream(
        downstream,
        rules,
        contextFor(sessionId),
        (result) => report(result, 'model_output', JSON.stringify(result.counts)),
      );
    } catch (error) {
      log(`sensitive-guard 【扫描异常】${error?.message ?? 'unknown'}，已放行原请求`);
      return next();
    }
  });

  /**
   * 严格模式的终止流 / Terminal stream.
   * 只产出一个 finish 块，adapter 不会被调用，请求体不会产生。
   */
  async function* refusalStream() {
    yield {
      type: 'finish',
      reason: { kind: 'error', failure: { code: 'CONTENT_REFUSED', message: BLOCK_NOTICE } },
    };
  }

  // ==================== 4. 子代理回传再扫描 ====================
  ctx.on('subagent/end', (info) => {
    try {
      if (config.bypassSanitize) return;
      if (!config.maskSubagentReturns) return;
      const sessionId = info?.sessionId ?? info?.agent?.id;
      const text = typeof info?.result === 'string' ? info.result : undefined;
      if (typeof text !== 'string') return;
      const result = runSanitize(text, rules, contextFor(sessionId));
      if (result.level !== LEVELS.pass) {
        report(result, 'subagent_return', text);
      }
    } catch {
      // 回传扫描失败不得影响子代理结果。
    }
  });

  ctx.on('agent/created', ({ agent }) => {
    try {
      if (agent?.id === undefined) return;
      whitelistFor(agent.id);
    } catch {
      // 忽略。
    }
  });
}

export default apply;
