/**
 * dsh-sensitive-guard — 敏感内容拦截与脱敏前置规则。
 *
 * 在请求发往中转网关之前执行，优先级高于路由、重试、模型调度。
 * Runs before a request reaches the gateway, ahead of routing, retry, and
 * dispatch.
 *
 * 两种模式 / Two modes:
 *
 * - `mask`（默认）脱敏放行：命中即替换，不中断任务。
 * - `block` 严格阻断：命中高风险时抛出 CONTENT_REFUSED，不发起请求。
 *
 * 三个挂载点 / Three hook points:
 *
 * 1. `agent/pre-step` — 用户输入进入 step 前脱敏，并分析附带图片。
 * 2. `tools/post-execute` — 工具输出落库前脱敏。
 * 3. `llm/stream` — 请求侧审计 + 响应侧脱敏 + 旁路检测。
 *
 * 不变量 / Invariants:
 *
 * - 单次正向替换；明文不落盘、不还原、不进日志。
 * - 会话内同一值恒定同一占位符；注册表只存 SHA-256 摘要。
 * - 任何内部异常都返回原决策，绝不让守卫本身弄坏一个回合。
 */

import { readFile, rm } from 'node:fs/promises';
import { probeOcr, recognizeImageWithBoxes, redactImage, readImagePixels, readFileHead, compressImage } from './ocr/runner.js';
import { readImageText, OCR_RULES } from './ocr/normalize.js';
import { mergeBoxes, padBox } from './ocr/redact.js';
import { privacyRules, detectContainer, looksBinary, decodeQr, NAME_ID_PAIR_RULE } from './ocr/detect.js';
import { maskResponseStream } from './response.js';
import { PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, buildRules, luhn, isExcluded, isHighEntropy } from './rules.js';
import { createRegistry, isWhitelisted, maskText, maskContent, maskValue, auditRequest } from './masking.js';

export { PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, buildRules, luhn, isExcluded, isHighEntropy };
export { createRegistry, isWhitelisted, maskText, maskContent, maskValue, auditRequest };
export { maskResponseStream, privacyRules, NAME_ID_PAIR_RULE };

/**
 * 构建含隐私规则的完整规则表 / Build the full rule table with privacy rules.
 *
 * 住址、病历、姓名+证件规则来自 OCR 层（`ocr/detect.js`），在这里注入，
 * 避免 `rules.js` 反向依赖造成循环引用。
 *
 * Address, medical, and name-plus-id rules live in the OCR layer; they are
 * injected here so `rules.js` never imports it.
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

/** 拦截提示 / Refusal notice for strict mode. */
export const BLOCK_NOTICE = '【敏感内容拦截，禁止提交】';

/**
 * 归一化配置 / Normalize the row config.
 * @param {unknown} raw
 */
export function resolveConfig(raw) {
  const config = raw && typeof raw === 'object' ? raw : {};
  return {
    // --- 模式 / mode ---
    enabled: config.enabled !== false,
    mode: config.mode === 'block' ? 'block' : 'mask',
    blockOnRisk: config.blockOnRisk === 'normal' ? 'normal' : 'high',

    // --- 挂载点开关 / hook switches ---
    maskUserMessages: config.maskUserMessages !== false,
    maskToolResults: config.maskToolResults !== false,
    maskResponses: config.maskResponses !== false,
    auditRequests: config.auditRequests !== false,

    // --- 规则开关 / rule switches ---
    maskUrls: config.maskUrls === true || config.maskUrls === 'all' ? 'all' : config.maskUrls === 'internal' ? 'internal' : false,
    privateUrlSuffixes: Array.isArray(config.privateUrlSuffixes) && config.privateUrlSuffixes.length > 0
      ? config.privateUrlSuffixes.filter((suffix) => typeof suffix === 'string')
      : undefined,
    maskDbCredentials: config.maskDbCredentials !== false,
    detectHighEntropy: config.detectHighEntropy !== false,
    detectAddresses: config.detectAddresses !== false,
    detectMedical: config.detectMedical !== false,
    detectBypass: config.detectBypass !== false,
    markBinary: config.markBinary !== false,
    disabledRules: Array.isArray(config.disabledRules) ? config.disabledRules.filter((id) => typeof id === 'string') : [],
    whitelist: Array.isArray(config.whitelist) ? config.whitelist.filter((token) => typeof token === 'string') : DEFAULT_WHITELIST,

    // --- 日志与告警 / logging and alerts ---
    logMasks: config.logMasks !== false,
    highRiskAlertAfter: Number.isInteger(config.highRiskAlertAfter) && config.highRiskAlertAfter > 0 ? config.highRiskAlertAfter : 6,
    perSessionStats: config.perSessionStats !== false,

    // --- 图片 / images ---
    maxImagesPerTurn: Number.isInteger(config.maxImagesPerTurn) && config.maxImagesPerTurn > 0 ? config.maxImagesPerTurn : 3,
    ocr: config.ocr !== false,
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

    // --- 会话临时白名单 / session-scoped whitelist ---
    sessionWhitelist: Array.isArray(config.sessionWhitelist) ? config.sessionWhitelist.filter((token) => typeof token === 'string') : [],
  };
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {unknown} rawConfig
 */
export function apply(ctx, rawConfig) {
  const config = resolveConfig(rawConfig);
  if (!config.enabled) return;

  const rules = buildFullRules(config);
  const ocrRules = [...OCR_RULES].filter((rule) => !config.disabledRules.includes(rule.id));

  /** sessionId → 占位符注册表 / placeholder registry */
  const registries = new Map();
  /** sessionId → 连续高风险计数 / consecutive high-risk count */
  const highRiskStreaks = new Map();
  /** sessionId → 已 OCR 的附件 / already-analyzed attachments */
  const scannedAttachments = new Map();
  /** sessionId → 会话临时白名单 / session-scoped whitelist */
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

  const log = (line) => {
    if (!config.logMasks) return;
    try {
      ctx.logger?.info?.(line);
    } catch {
      // 日志失败不得改变判定 / logging never changes a decision.
    }
  };

  /**
   * 记录一次脱敏 / Record one masking outcome.
   *
   * 规格要求日志分类并标注命中类型，且不输出原文。
   * The log carries a level and hit kinds, never the matched value.
   */
  const reportMask = (sessionId, result, scope) => {
    const summary = Object.entries(result.counts ?? {})
      .map(([placeholder, count]) => `${placeholder}×${count}`)
      .join(' ');
    const kinds = result.kinds && result.kinds.size > 0 ? [...result.kinds].join('/') : '其他';
    const label = result.risk === 'high' ? '【⚠️已脱敏-高风险】' : '【⚠️已脱敏-普通】';
    log(`sensitive-guard ${label}[${scope}] 命中=${kinds}${summary ? ` ${summary}` : ''}`);

    if (result.risk !== 'high') return;
    const key = keyOf(sessionId);
    const streak = (highRiskStreaks.get(key) ?? 0) + 1;
    highRiskStreaks.set(key, streak);
    if (streak === config.highRiskAlertAfter) {
      log(`sensitive-guard 【⚠️告警】本会话已连续 ${streak} 次命中高风险脱敏，请确认上下文是否包含真实凭据`);
    }
  };

  /** 严格模式下是否应当阻断 / Whether strict mode refuses this hit. */
  const shouldBlock = (risk) => {
    if (config.mode !== 'block') return false;
    if (risk === 'high') return true;
    return risk === 'normal' && config.blockOnRisk === 'normal';
  };

  // ==================== OCR 可用性探测 / OCR probe ====================
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

  // ==================== 图片分析 / image analysis ====================
  /**
   * 分析一条消息里的图片：二进制标记、二维码、OCR、涂改、压缩。
   *
   * 全程不抛异常：任何一步失败都只记录并放行。
   * Never throws: every failure is reported and the image passes.
   */
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
          log(`sensitive-guard 【⚠️放行-OCR超限】本轮仅分析前 ${config.ocrMaxImagesPerTurn} 张，其余未做 OCR`);
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

        // 二进制内容不解析内部，只标记。
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
              const masked = maskText(payload, ocrRules, { rules: ocrRules, config, registry: registryFor(sessionId), sessionWhitelist: whitelist });
              if (masked.risk !== undefined) {
                log('sensitive-guard 【⚠️二维码命中】码内含敏感内容，画内码无法就地改写，已标记风险');
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
          log(`sensitive-guard 【⚠️OCR识别不可靠】${read.unreliable.length} 行文本未达可信阈值，已忽略`);
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
          // 无需涂改，但仍需降分辨率。
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
            const saved = await ctx.attachments.saveImage({
              data,
              mediaType: 'image/png',
              name: block.attachment.name ?? 'redacted.png',
            });
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

  // ==================== 1. 用户输入 / user input ====================
  ctx.on('agent/pre-step', async ({ agent, messages }, next) => {
    const decision = await next();
    try {
      const sessionId = agent?.id;
      if (Array.isArray(messages) && messages.some((message) => message?.source?.kind === 'user')) {
        highRiskStreaks.delete(keyOf(sessionId));
      }
      if (!config.maskUserMessages) return decision;
      if (decision?.kind !== 'enter' || !Array.isArray(decision.messages)) return decision;

      const context = {
        rules,
        config,
        registry: registryFor(sessionId),
        sessionWhitelist: whitelistFor(sessionId),
      };
      const totals = { counts: {}, risk: undefined, kinds: new Set() };
      let changed = false;

      const absorb = (masked) => {
        for (const [placeholder, count] of Object.entries(masked.counts)) {
          totals.counts[placeholder] = (totals.counts[placeholder] ?? 0) + count;
        }
        for (const kind of masked.kinds) totals.kinds.add(kind);
        if (masked.risk === 'high') totals.risk = 'high';
        else if (masked.risk === 'normal' && totals.risk === undefined) totals.risk = 'normal';
      };

      const maskedMessages = decision.messages.map((message) => {
        if (typeof message?.content === 'string') {
          const masked = maskText(message.content, rules, context);
          if (masked.text === message.content) return message;
          changed = true;
          absorb(masked);
          return { ...message, content: masked.text };
        }
        const masked = maskContent(message?.content, rules, context);
        if (masked.content === message?.content) return message;
        changed = true;
        absorb(masked);
        return { ...message, content: masked.content };
      });

      // 图片分析：OCR 文本走脱敏规则，命中行涂改后替换图片块。
      let finalMessages = maskedMessages;
      if (config.ocr && ocrAvailable) {
        const analysis = await analyzeImages(decision.messages, sessionId);
        if (analysis.found.length > 0) {
          for (const line of analysis.found) {
            absorb(maskText(line.text, ocrRules, { rules: ocrRules, config, registry: registryFor(sessionId), sessionWhitelist: whitelistFor(sessionId) }));
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

      if (!changed && totals.risk === undefined) {
        log('sensitive-guard 【✅无敏感】');
        return decision;
      }

      if (totals.risk !== undefined) {
        reportMask(sessionId, totals, '对话明文');
        if (shouldBlock(totals.risk)) {
          log(`sensitive-guard 【⛔严格模式阻断】命中=${[...totals.kinds].join('/') || '其他'}`);
          return { kind: 'reject' };
        }
      }
      return { ...decision, messages: finalMessages };
    } catch (error) {
      log(`sensitive-guard 【⚠️守卫异常】${error?.message ?? 'unknown'}，放行原决策`);
      return decision;
    }
  });

  // ==================== 2. 工具输出 / tool output ====================
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next();
    try {
      if (!config.maskToolResults) return decision;
      if (decision?.kind !== 'accept') return decision;

      const sessionId = exec?.agent?.id;
      const context = {
        rules,
        config,
        registry: registryFor(sessionId),
        sessionWhitelist: whitelistFor(sessionId),
      };
      const totals = { counts: {}, risk: undefined, kinds: new Set() };
      let changed = false;
      let nextDecision = decision;

      if (Array.isArray(decision.content)) {
        const masked = maskContent(decision.content, rules, context);
        if (masked.content !== decision.content) {
          changed = true;
          Object.assign(totals.counts, masked.counts);
          for (const kind of masked.kinds) totals.kinds.add(kind);
          totals.risk = masked.risk;
          nextDecision = { ...nextDecision, content: masked.content };
        }
      }
      if (decision.value !== undefined && nextDecision.content === undefined) {
        const masked = maskValue(decision.value, rules, context);
        if (masked.value !== decision.value) {
          changed = true;
          Object.assign(totals.counts, masked.counts);
          for (const kind of masked.kinds) totals.kinds.add(kind);
          totals.risk = masked.risk;
          nextDecision = { ...nextDecision, value: masked.value };
        }
      }
      if (!changed) return decision;
      reportMask(sessionId, totals, '工具输出');
      return nextDecision;
    } catch (error) {
      log(`sensitive-guard 【⚠️守卫异常】${error?.message ?? 'unknown'}，放行原决策`);
      return decision;
    }
  });

  // ==================== 3. 请求审计 + 响应脱敏 / audit and response ====================
  ctx.on('llm/stream', (options, next) => {
    try {
      const sessionId = options?.sessionId;

      // 旁路检测：没有会话归属的请求不是 Agent 循环构建的。
      if (config.detectBypass && sessionId === undefined) {
        log('sensitive-guard 【⚠️旁路风险】检测到无会话归属的直连请求，仍执行脱敏审计');
      }

      // 请求侧审计：循环构建的请求是深冻结的，只读不改。
      if (config.auditRequests) {
        const verdict = auditRequest(options, rules, {
          rules,
          config,
          registry: registryFor(sessionId),
          sessionWhitelist: whitelistFor(sessionId),
        });
        if (verdict.risk !== undefined) {
          const summary = Object.entries(verdict.counts).map(([placeholder, count]) => `${placeholder}×${count}`).join(' ');
          log(`sensitive-guard 【⚠️放行-请求侧残余】命中=${[...verdict.kinds].join('/') || '其他'} ${summary}（请求体已冻结，未改写）`);
          if (shouldBlock(verdict.risk)) {
            log(`sensitive-guard 【⛔严格模式阻断】请求侧命中高风险，不发起请求`);
            return refusalStream();
          }
        }
        if (verdict.images > config.maxImagesPerTurn) {
          log(`sensitive-guard 【⚠️放行-图片超限】本轮 ${verdict.images} 张，上限 ${config.maxImagesPerTurn}，建议分批`);
        }
      }

      const downstream = next();
      if (!config.maskResponses) return downstream;

      // 响应侧脱敏：用改写后的 block-end 覆盖已闭合的文本块。
      return maskResponseStream(
        downstream,
        rules,
        {
          rules,
          config,
          registry: registryFor(sessionId),
          sessionWhitelist: whitelistFor(sessionId),
        },
        (masked) => reportMask(sessionId, masked, '模型返回'),
      );
    } catch (error) {
      log(`sensitive-guard 【⚠️守卫异常】${error?.message ?? 'unknown'}，放行原请求`);
      return next();
    }
  });

  /**
   * 严格模式的终止流 / Terminal stream for strict mode.
   *
   * 只产出一个 finish 块，adapter 不会被调用，请求体不会产生。
   * Emits one terminal finish chunk; no adapter call, no request body.
   */
  async function* refusalStream() {
    yield {
      type: 'finish',
      reason: { kind: 'error', failure: { code: 'CONTENT_REFUSED', message: BLOCK_NOTICE } },
    };
  }

  /** 供外部标记误判 / Mark a false positive for the current session. */
  ctx.on('agent/created', ({ agent }) => {
    try {
      if (agent?.id === undefined) return;
      whitelistFor(agent.id);
    } catch {
      // 忽略 / ignored.
    }
  });
}

export default apply;
