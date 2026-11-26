/**
 * dsh-sensitive-guard — 敏感内容拦截与脱敏。
 *
 * 本文件只做三件事：装配模块、注册挂载点、把扫描结果翻译成动作。
 * 判定逻辑在 `rules.js` 与 `masking.js`，图片处理在 `image-pipeline.js`，
 * 会话状态在 `session-state.js`，日志在 `logger.js`。
 *
 * This file does three things: wire the modules, register the hooks, and turn a
 * scan result into an action. Rules live in `rules.js`, scanning in
 * `masking.js`, images in `image-pipeline.js`, session state in
 * `session-state.js`, logging in `logger.js`.
 *
 * 三级分类 / Three levels:
 *
 * - **BLOCK** 清洗后继续：敏感片段替换为占位符，任务不中断。
 * - **MASK** 脱敏：替换后写入。
 * - **PASS** 放行：原文写入。
 *
 * 唯一的拦截是绕过攻击指令：它要求守卫停工，不属于可脱敏处理的内容。
 * The only refusal is a bypass-attack instruction: it asks the guard to stand
 * down, which is not content that can be masked.
 *
 * 挂载点 / Hook points:
 *
 * 0. `typertGateway.dispatchRpc` — 请求体前置清洗，明文不进 inbox。
 * 1. `agent/pre-step` — 绕过判定 + 用户输入分级扫描 + 图片分析。
 * 2. `tools/post-execute` — 工具与子代理输出入库前二次分级。
 * 3. `llm/stream` — 请求侧审计 + 响应侧流式扫描。
 * 4. `subagent/end` — 子代理回传再扫描。
 */

import { probeOcr } from './ocr/runner.js';
import { OCR_RULES } from './ocr/normalize.js';
import { privacyRules, NAME_ID_PAIR_RULE } from './ocr/detect.js';
import { maskResponseStream, maskBase64Payloads } from './response.js';
import {
  interceptPayload, interceptPromptBody, replaceRequestBody,
  isPromptEnvelope, isPromptEndpoint, sanitizeArgs, sanitizeWithAttachments,
} from './prebody.js';
import { detectBypassAttempt, userTextOf, BYPASS_KIND } from './bypass.js';
import {
  PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, HIGH_RISK_KINDS, LEVELS,
  buildRules, luhn, isExcluded, isHighEntropy, isBase64Like, validateBankCard, shannonEntropy,
  CHUNK_SIZE, MAX_RECURSE_DEPTH,
} from './rules.js';
import {
  createRegistry, isWhitelistedValue, scanText, scanDeep, scanValue, scanContent,
  runSanitize, auditRequest, structuredLog, maskPreview, inputHash, chunkText,
} from './masking.js';
import { SessionState } from './session-state.js';
import { ResultAccumulator } from './accumulator.js';
import { GuardLogger, shouldAlertStreak } from './logger.js';
import { analyzeImages, applyReplacements } from './image-pipeline.js';

export {
  PLACEHOLDERS, DEFAULT_WHITELIST, HIT_KINDS, HIGH_RISK_KINDS, LEVELS,
  buildRules, luhn, isExcluded, isHighEntropy, isBase64Like, validateBankCard, shannonEntropy,
  CHUNK_SIZE, MAX_RECURSE_DEPTH,
};
export {
  createRegistry, isWhitelistedValue, scanText, scanDeep, scanValue, scanContent,
  runSanitize, auditRequest, structuredLog, maskPreview, inputHash, chunkText,
};
export { maskResponseStream, maskBase64Payloads, privacyRules, NAME_ID_PAIR_RULE };
export { interceptPayload, interceptPromptBody, replaceRequestBody, isPromptEnvelope, isPromptEndpoint, sanitizeArgs, sanitizeWithAttachments };
export { detectBypassAttempt, userTextOf, BYPASS_KIND };
export { SessionState, ResultAccumulator, GuardLogger, shouldAlertStreak };
export { analyzeImages, applyReplacements };

/** 拦截提示 / Refusal notice. */
export const BLOCK_NOTICE = '【阻断拦截】检测到阻断类敏感内容，不写入 session';

/** 绕过攻击提示 / Bypass notice. */
export const BYPASS_NOTICE = '【检测到绕过脱敏的指令，已拦截并上报】';

/**
 * 构建含隐私规则的完整规则表 / Build the full rule table with privacy rules.
 *
 * 住址、病历、姓名+证件规则来自 OCR 层，在这里注入，避免 `rules.js`
 * 反向依赖造成循环引用。
 *
 * Address, medical, and name-plus-id rules live in the OCR layer; injecting
 * them here keeps `rules.js` free of that dependency.
 *
 * @param {object} config 归一化配置 / normalized config
 * @returns {object[]}
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
    bypassSanitize: config.bypassSanitize === true,
    partialBlock: config.partialBlock === true,
    diagnoseTransport: config.diagnoseTransport === true,

    // --- 模式 / mode ---
    blockBypass: config.blockBypass !== false,

    // --- 挂载点开关 / hook switches ---
    interceptPromptBody: config.interceptPromptBody !== false,
    maskUserMessages: config.maskUserMessages !== false,
    maskToolResults: config.maskToolResults !== false,
    // 默认关闭响应侧脱敏：用户要求「发出去的脱敏，助手发回来的不脱敏」。
    // 输入侧（用户消息、工具结果）照常脱敏，厂商看不到明文；
    // 输出侧不再清洗，助手的回复原样显示给用户。
    // 注意：输出是厂商模型生成的，关闭清洗不改变厂商已看到的内容。
    maskResponses: config.maskResponses === true,
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
  config.disabledRulesSet = new Set(config.disabledRules);
  const ocrRules = OCR_RULES.filter((rule) => !config.disabledRulesSet.has(rule.id));
  const state = new SessionState(config);
  const logger = new GuardLogger(config, ctx.logger);
  const contextFor = (sessionId) => state.contextFor(sessionId, rules);

  /** 把一次扫描结果记入日志并按需告警 / Log one result and alert when due. */
  const publish = (result, source, rawText) => {
    logger.report(result, source, rawText);
    if (result.level !== LEVELS.block) return;
    const streak = state.bumpStreak(source);
    if (shouldAlertStreak(streak, config.highRiskAlertAfter)) {
      logger.alert(`本会话已连续 ${streak} 次命中阻断级内容，请确认上下文是否包含真实凭据`, result);
    }
  };

  /**
   * 扫描一条消息的文本内容 / Scan one message's text content.
   * @returns {{message: object, result: object}}
   */
  const scanMessage = (message, context) => {
    if (typeof message?.content === 'string') {
      const result = runSanitize(message.content, rules, context);
      return { message: result.content === message.content ? message : { ...message, content: result.content }, result };
    }
    const result = scanContent(message?.content, rules, context);
    return { message: result.content === message?.content ? message : { ...message, content: result.content }, result };
  };

  // ==================== OCR 探测 ====================
  let ocrAvailable = false;
  if (config.ocr) {
    if (config.ocrMode === 'upstream') {
      logger.warn('风险提示 OCR 为上游模式，原图会外传至外部服务');
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
        logger.info(`✅OCR就绪 backend=${probe.backend} mode=${config.ocrMode} platform=${probe.platform}`);
      } else {
        logger.warn(`OCR不可用 ${probe.reason ?? 'unknown'}（backend=${probe.backend}），图片仅做元数据清理`);
      }
    }).catch((error) => {
      ocrAvailable = false;
      logger.warn(`OCR探测失败 ${error?.message ?? 'unknown'}`);
    });
  }

  // ==================== 0. RPC 前置清洗 ====================
  /**
   * 在 RPC 层改写 `session/prompt` 的 payload，使明文不进入 inbox。
   *
   * `/api` 通道已被 `typertGateway` 注册为唯一 interceptor，二次注册会抛
   * "already has an interceptor"。因此包装 Gateway 自己的 `dispatchRpc`：
   * 它正是那个 interceptor 的转发目标，位置等价。
   *
   * 用 `ctx.inject` 等待服务就绪：`apply()` 执行时 `typertGateway` 可能尚未
   * 挂载，直接 `ctx.get()` 会拿到 undefined，包装就静默失效。
   *
   * The `/api` channel already belongs to `typertGateway`, so a second
   * interceptor registration throws. Wrapping the gateway's own `dispatchRpc`
   * reaches the same point. `ctx.inject` waits for the service, because at
   * `apply()` time it may not be mounted yet and a bare `ctx.get()` would
   * silently skip the wrapper.
   */
  if (config.interceptPromptBody) {
    ctx.inject(['typertGateway'], (gatewayCtx) => {
      const gateway = gatewayCtx.typertGateway;
      if (gateway === undefined || typeof gateway.dispatchRpc !== 'function') {
        logger.warn('RPC前置拦截不可用 typertGateway.dispatchRpc 不存在，仅依赖 pre-step');
        return;
      }
      const original = gateway.dispatchRpc;
      gateway.dispatchRpc = async function patchedDispatchRpc(endpoint, payload, signal, peer) {
        if (config.bypassSanitize) return original.call(this, endpoint, payload, signal, peer);
        try {
          const outcome = interceptPayload(endpoint, payload, rules, contextFor, (line) => logger.line(line), {
            diagnose: config.diagnoseTransport,
          });
          const nextPayload = outcome.handled ? outcome.payload : payload;
          return await original.call(this, endpoint, nextPayload, signal, peer);
        } catch (error) {
          logger.warn(`RPC前置拦截异常 ${error?.message ?? 'unknown'}，原样放行`);
          return original.call(this, endpoint, payload, signal, peer);
        }
      };
      gatewayCtx.effect(() => () => {
        // 卸载时还原原方法，避免 HMR 叠加多层包装。
        gateway.dispatchRpc = original;
      }, 'sensitive-guard: dispatchRpc wrapper');
      logger.info('✅RPC前置拦截已启用 包装 typertGateway.dispatchRpc，覆盖 inbox 前置清洗');
    });
  }

  // ==================== HTTP 兜底 ====================
  /**
   * 真实 HTTP 部署时的第二道防线。
   *
   * Desktop 的 Web GUI 走进程内 fetch，不触发此事件；它只在独立 HTTP 服务
   * 或远程访问时生效。保留它是因为远程场景下 RPC 包装覆盖不到。
   *
   * The second line of defence for real HTTP deployments. Desktop's Web GUI
   * uses an in-process fetch and never fires this; it matters for standalone
   * HTTP serving and remote access, where the RPC wrapper is not enough.
   */
  ctx.on('connection/request', async (request, _response, next) => {
    try {
      if (config.bypassSanitize || !config.interceptPromptBody) return next();
      const outcome = await interceptPromptBody(request, rules, contextFor, (line) => logger.line(line), {
        diagnose: config.diagnoseTransport,
      });
      if (outcome.replay !== undefined) replaceRequestBody(request, outcome.replay);
      return next();
    } catch (error) {
      logger.warn(`HTTP前置拦截异常 ${error?.message ?? 'unknown'}，原样放行`);
      return next();
    }
  });

  // ==================== 1. pre-step ====================
  ctx.on('agent/pre-step', async ({ agent, messages }, next) => {
    const decision = await next();
    const sessionId = agent?.id;
    try {
      if (config.bypassSanitize) {
        logger.warn('调试旁路已开启 跳过全部敏感检测，生产环境请关闭');
        return decision;
      }

      if (Array.isArray(messages) && messages.some((message) => message?.source?.kind === 'user')) {
        state.resetStreak(sessionId);
      }
      if (!config.maskUserMessages) return decision;
      if (decision?.kind !== 'enter' || !Array.isArray(decision.messages)) return decision;

      // 含图片的消息完全直通 / Pass image-bearing messages through untouched.
      // 实测：只要插件处理含 image block 的消息，GUI 就报「这个附件发不了」；
      // 关闭插件即可发送。任何对 decision/messages 的重写（哪怕只是 map 生成新
      // 数组、或 OCR 命中后 totals.changed 触发 {...decision, messages} 重建）都会
      // 破坏附件的宿主引用。图片消息一律跳过脱敏/OCR/涂改，行为等同插件关闭，
      // 保证附件原样送达。纯文本消息不受影响。
      // Any rewrite of an image-bearing decision breaks DSH's attachment handle.
      // Pass such messages straight through; text-only masking stays intact.
      if (decision.messages.some((message) => Array.isArray(message?.content)
        && message.content.some((block) => block?.type === 'image'))) {
        logger.info('[user_input] 含图片消息直通，跳过脱敏/OCR，附件原样发送');
        return decision;
      }

      // 绕过判定优先于脱敏：命中即拦截。
      if (config.detectBypass && config.blockBypass) {
        for (const message of decision.messages) {
          if (message?.source?.kind !== 'user') continue;
          const text = userTextOf(message.content);
          const verdict = detectBypassAttempt(text);
          if (!verdict.bypass) continue;
          logger.report(
            { level: LEVELS.block, kinds: new Set([BYPASS_KIND]), hits: [{ ruleId: verdict.rule, kind: BYPASS_KIND, level: LEVELS.block }], counts: {} },
            'user_input',
            text,
          );
          logger.error(`绕过攻击尝试 rule=${verdict.rule} 已拦截，不写 session、不转发模型`);
          return { kind: 'reject' };
        }
      }

      const context = contextFor(sessionId);
      const totals = new ResultAccumulator();
      const scannedMessages = decision.messages.map((message) => {
        const { message: nextMessage, result } = scanMessage(message, context);
        totals.add(result);
        return nextMessage;
      });

      // 图片分析：OCR 文本走同一套分级规则，命中行涂改。
      let finalMessages = scannedMessages;
      if (config.ocr && ocrAvailable) {
        const analysis = await analyzeImages(decision.messages, {
          config,
          logger,
          attachments: ctx.attachments,
          scanned: state.scannedFor(sessionId),
          context,
          ocrRules,
        });
        if (analysis.found.length > 0) {
          for (const line of analysis.found) totals.add(runSanitize(line.text, ocrRules, context));
          logger.warn(`OCR命中 图片内含敏感文字 ${analysis.found.length} 行`);
        }
        const applied = applyReplacements(scannedMessages, analysis.replacements);
        finalMessages = applied.messages;
        if (applied.changed) totals.changed = true;
      }

      // BLOCK 与 MASK 都只做清洗，任务继续。唯一的拦截已在上面的绕过判定。
      if (totals.matched) {
        publish(totals.toResult(), 'user_input', JSON.stringify(totals.counts));
        return totals.changed ? { ...decision, messages: finalMessages } : decision;
      }

      logger.info('[user_input] level=PASS 无敏感内容');
      return decision;
    } catch (error) {
      logger.warn(`扫描异常 ${error?.message ?? 'unknown'}，已放行原决策`);
      return decision;
    }
  });

  // ==================== 2. post-execute ====================
  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next();
    const sessionId = exec?.agent?.id;
    try {
      if (config.bypassSanitize) return decision;
      if (!config.maskToolResults) return decision;
      if (decision?.kind !== 'accept') return decision;

      const context = contextFor(sessionId);
      const totals = new ResultAccumulator();

      // 关键：工具结果在 waterfall 的第二个参数 `result` 里，不在 `decision` 里。
      // `next()` 返回的是下游 decision（默认 {kind:'accept'}），没有 content/value。
      // 旧实现只扫 decision，导致文件内容（明文）原样流入模型与中转。
      // The tool result is the 2nd waterfall arg, NOT the decision. Scan `result`
      // and return a decision whose content/value carries the masked text.
      let nextDecision = decision;
      if (result?.content !== undefined) {
        const scanned = sanitizeArgs(result.content, rules, context);
        totals.add(scanned);
        if (scanned.changed) nextDecision = { ...nextDecision, content: scanned.value };
      }
      if (result?.value !== undefined && result?.content === undefined && nextDecision.content === undefined) {
        const scanned = sanitizeArgs(result.value, rules, context);
        totals.add(scanned);
        if (scanned.changed) nextDecision = { ...nextDecision, value: scanned.value };
      }

      if (!totals.matched) return decision;
      publish(totals.toResult(), 'tool_result', JSON.stringify(totals.counts));
      logger.info(`工具结果已前置脱敏 level=${totals.level}，明文未进入模型与中转`);
      return totals.changed ? nextDecision : decision;
    } catch (error) {
      logger.warn(`扫描异常 ${error?.message ?? 'unknown'}，已放行工具结果`);
      return decision;
    }
  });

  // ==================== 3. llm/stream ====================
  ctx.on('llm/stream', (options, next) => {
    const sessionId = options?.sessionId;
    try {
      if (config.bypassSanitize) {
        logger.warn('调试旁路已开启 跳过全部敏感检测');
        return next();
      }

      if (config.detectBypass && sessionId === undefined) {
        logger.warn('旁路风险 检测到无会话归属的直连请求，仍执行扫描');
      }

      if (config.auditRequests) {
        const verdict = auditRequest(options, rules, contextFor(sessionId));
        if (verdict.level !== LEVELS.pass) {
          // 请求体已深冻结，插件无法改写；清洗发生在 pre-step 与 RPC 层。
          // A loop-built request is deep-frozen; cleaning happens earlier.
          publish({ ...verdict, level: verdict.level }, 'request_audit', JSON.stringify(verdict.counts));
          logger.warn('请求侧残余 请求体已冻结，未改写，仅告警');
        }
        if (verdict.images > config.maxImagesPerTurn) {
          logger.warn(`放行-图片超限 本轮 ${verdict.images} 张，上限 ${config.maxImagesPerTurn}`);
        }
      }

      const downstream = next();
      if (!config.maskResponses) return downstream;

      return maskResponseStream(
        downstream,
        rules,
        contextFor(sessionId),
        (result) => publish(result, 'model_output', JSON.stringify(result.counts)),
      );
    } catch (error) {
      logger.warn(`扫描异常 ${error?.message ?? 'unknown'}，已放行原请求`);
      return next();
    }
  });

  // ==================== 4. 子代理回传 ====================
  ctx.on('subagent/end', (info) => {
    try {
      if (config.bypassSanitize) return;
      if (!config.maskSubagentReturns) return;
      const sessionId = info?.sessionId ?? info?.agent?.id;
      const text = typeof info?.result === 'string' ? info.result : undefined;
      if (typeof text !== 'string') return;
      const result = runSanitize(text, rules, contextFor(sessionId));
      if (result.level !== LEVELS.pass) publish(result, 'subagent_return', text);
    } catch {
      // 回传扫描失败不得影响子代理结果。
    }
  });

  // ==================== 生命周期 ====================
  ctx.on('agent/created', ({ agent }) => {
    try {
      if (agent?.id === undefined) return;
      state.whitelistFor(agent.id);
    } catch {
      // 忽略。
    }
  });

  /**
   * 会话销毁时释放状态。
   *
   * 没有这一步，长跑的 Host 会为每个打开过的会话永久保留注册表与计数。
   * 这是一处真实的内存泄漏，之前的版本没有处理。
   *
   * Without this, a long-running Host keeps a registry and counters for every
   * session it ever opened. That was a real leak in earlier versions.
   */
  ctx.on('session/disposed', (session) => {
    try {
      if (session?.id !== undefined) state.forget(session.id);
    } catch {
      // 忽略。
    }
  });
}

export default apply;
