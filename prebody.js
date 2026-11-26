/**
 * 请求体前置拦截 / Pre-inbox request interception.
 *
 * 为什么需要这一层 / Why this layer exists:
 *
 * DSH 在 API 层 `agent.followup()` 就把用户输入写入 inbox，`agent/pre-step`
 * 在此之后才触发。因此 pre-step 只能保证「session 与请求」不含明文，
 * 无法阻止明文进入 inbox。
 *
 * DSH writes the prompt into the inbox inside the API layer, before
 * `agent/pre-step` runs, so pre-step cannot keep plaintext out of the inbox.
 *
 * 正确的钩子 / The correct hook:
 *
 * `ctx.connection.rpc.intercept('/api', matches, handler)` 是 DSH 官方提供的
 * RPC 拦截器，在请求体被解析成 payload 之后、业务方法被调用之前拿到它。
 *
 * 早先尝试的 `connection/request` 事件只在真实 HTTP 请求上触发；Desktop 的
 * Web GUI 走进程内 fetch，绕过了那一层。RPC interceptor 对两种传输都生效，
 * 因为它挂在 fetch handler 之前。
 *
 * `ctx.connection.rpc.intercept('/api', matches, handler)` is the official RPC
 * interceptor: it sees the parsed payload before the business method runs. The
 * `connection/request` event only fires for real HTTP traffic; Desktop's Web GUI
 * uses an in-process fetch and bypassed it. The interceptor covers both.
 *
 * 失败即放行 / Fail-open:
 *
 * 任何一步出错都原样放行原始 payload。这一层绝不因为自己的问题破坏一次对话。
 * Any failure passes the original payload through untouched.
 */

import { runSanitize, structuredLog, inputHash } from './masking.js';
import { LEVELS } from './rules.js';

/**
 * 携带用户文本的 RPC 方法 / RPC methods that carry user text.
 *
 * endpoint 形如 `session/prompt`，取最后一段判定。
 * The endpoint looks like `session/prompt`; the last segment is the method.
 */
const PROMPT_METHODS = new Set(['prompt', 'steer', 'followup', 'send', 'submit']);

/** 只处理这些命名空间 / namespaces worth inspecting. */
const PROMPT_NAMESPACES = new Set(['session', 'sessions', 'agent', 'conversation']);

/**
 * 判断一个 endpoint 是否携带用户文本 / Whether one endpoint carries user text.
 * @param {string} endpoint
 * @returns {boolean}
 */
export function isPromptEndpoint(endpoint) {
  if (typeof endpoint !== 'string') return false;
  const segments = endpoint.split('/').filter((part) => part.length > 0);
  if (segments.length === 0) return false;
  const method = segments[segments.length - 1].toLowerCase();
  const namespace = segments[0].toLowerCase();
  return PROMPT_METHODS.has(method) && PROMPT_NAMESPACES.has(namespace);
}

/**
 * 兼容旧接口：判断一个 RPC 报文是否携带用户文本。
 * @param {unknown} payload
 * @returns {boolean}
 */
export function isPromptEnvelope(payload) {
  if (payload === null || typeof payload !== 'object') return false;
  const namespace = String(payload.namespace ?? '').toLowerCase();
  const method = String(payload.method ?? '').toLowerCase();
  if (!PROMPT_NAMESPACES.has(namespace)) return false;
  if (!PROMPT_METHODS.has(method)) return false;
  return payload.args !== undefined && payload.args !== null;
}

/**
 * 递归处理 payload 里的文本字段 / Walk a payload and sanitize text fields.
 *
 * 只改字符串叶子，保留字段名与数组结构。`sessionId`、`requestId` 这类
 * 标识符即使被规则命中也不会被替换，因为它们不是用户内容。
 *
 * Only string leaves change; key names and array shapes are preserved.
 * Identifier fields are skipped because they are not user content.
 *
 * @param {unknown} value
 * @param {object[]} rules
 * @param {object} context
 * @param {number} depth
 * @param {string} [key] 当前字段名 / current field name
 * @returns {{value: unknown, level: string, counts: object, kinds: Set<string>, hits: object[], changed: boolean}}
 */
export function sanitizeArgs(value, rules, context, depth = 0, key = '') {
  const empty = { value, level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], changed: false };
  if (depth > 8) return empty;

  // 标识符字段不参与脱敏，否则会破坏会话定位。
  if (IDENTIFIER_KEYS.has(key)) return empty;

  if (typeof value === 'string') {
    const result = runSanitize(value, rules, context);
    if (result.level === LEVELS.pass) return empty;
    return {
      value: result.content,
      level: result.level,
      counts: result.counts,
      kinds: result.kinds,
      hits: result.hits,
      changed: result.content !== value,
    };
  }

  if (Array.isArray(value)) {
    const counts = {};
    const kinds = new Set();
    const hits = [];
    let level = LEVELS.pass;
    let changed = false;
    const next = value.map((item) => {
      const result = sanitizeArgs(item, rules, context, depth + 1, key);
      if (result.changed) changed = true;
      for (const [placeholder, count] of Object.entries(result.counts)) {
        counts[placeholder] = (counts[placeholder] ?? 0) + count;
      }
      for (const kind of result.kinds) kinds.add(kind);
      hits.push(...result.hits);
      if (result.level === LEVELS.block) level = LEVELS.block;
      else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
      return result.value;
    });
    return { value: changed ? next : value, level, counts, kinds, hits, changed };
  }

  if (value !== null && typeof value === 'object') {
    // 附件容器整体跳过：保留文件名/路径/哈希原样，避免破坏图片附件解析。
    if (isAttachmentContainer(value, key)) return empty;
    const counts = {};
    const kinds = new Set();
    const hits = [];
    let level = LEVELS.pass;
    let changed = false;
    const next = {};
    for (const [entryKey, item] of Object.entries(value)) {
      const result = sanitizeArgs(item, rules, context, depth + 1, entryKey);
      if (result.changed) changed = true;
      for (const [placeholder, count] of Object.entries(result.counts)) {
        counts[placeholder] = (counts[placeholder] ?? 0) + count;
      }
      for (const kind of result.kinds) kinds.add(kind);
      hits.push(...result.hits);
      if (result.level === LEVELS.block) level = LEVELS.block;
      else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
      next[entryKey] = result.value;
    }
    return { value: changed ? next : value, level, counts, kinds, hits, changed };
  }

  return empty;
}

/** 标识符字段，永不脱敏 / identifier fields that are never masked. */
const IDENTIFIER_KEYS = new Set([
  'sessionId', 'requestId', 'rpcId', 'id', 'messageId', 'callId',
  'clientTimeZone', 'mode', 'type', 'kind', 'role', 'source',
]);

/**
 * 附件元数据子树不做文本脱敏 / attachment metadata is never text-masked.
 *
 * 原因：`attachment.name` 常含图片的绝对路径（如 `C:\...\屏幕截图.png`），
 * 一旦被 local-path / 其它规则改写，DSH 就无法按原文件名解析附件，
 * 结果就是图片发送失败。附件的身份与定位字段必须原样透传。
 * Attachment names often carry absolute paths; rewriting them breaks DSH's
 * attachment resolution and makes image sending fail. Pass them through.
 */
function isAttachmentContainer(value, key) {
  if (key === 'attachment' || key === 'attachments') return true;
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    // 图片块本身：有 type=image 且带 attachment
    if (value.type === 'image' && 'attachment' in value) return true;
  }
  return false;
}

/**
 * 含附件消息的脱敏：重建对象树，但 image 块与 attachment 复用原对象引用。
 * 这样既能在深冻结 payload 上完成文字脱敏，又不破坏 DSH 的附件身份。
 * Mask with attachments: rebuild the tree but reuse image-block references.
 */
export function sanitizeWithAttachments(value, rules, context, depth = 0) {
  const totals = { level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], changed: false };
  if (depth > 8 || value === null || typeof value !== 'object') {
    return { value, ...totals };
  }

  // 附件容器 / image 块：整体复用原引用，绝不重建。
  if (isAttachmentContainer(value, '') || value.type === 'image') {
    return { value, ...totals };
  }

  if (Array.isArray(value)) {
    let changed = false;
    const next = value.map((item) => {
      const r = sanitizeWithAttachments(item, rules, context, depth + 1);
      if (r.value !== item) changed = true;
      absorbInto(totals, r);
      return r.value;
    });
    return { value: changed ? next : value, ...totals };
  }

  let changed = false;
  const next = {};
  for (const [key, child] of Object.entries(value)) {
    if (IDENTIFIER_KEYS.has(key)) { next[key] = child; continue; }
    if (key === 'text' && typeof child === 'string' && value.type === 'text') {
      const result = runSanitize(child, rules, context);
      if (result.level !== LEVELS.pass && result.content !== child) {
        next[key] = result.content;
        changed = true;
        absorbInto(totals, result);
      } else {
        next[key] = child;
      }
      continue;
    }
    const r = sanitizeWithAttachments(child, rules, context, depth + 1);
    if (r.value !== child) changed = true;
    absorbInto(totals, r);
    next[key] = r.value;
  }
  return { value: changed ? next : value, ...totals, changed };
}

/** 把子结果合并进 totals / merge a child result into totals. */
function absorbInto(totals, r) {
  for (const [p, c] of Object.entries(r.counts ?? {})) totals.counts[p] = (totals.counts[p] ?? 0) + c;
  for (const k of r.kinds ?? []) totals.kinds.add(k);
  if (r.hits) totals.hits.push(...r.hits);
  if (r.level === LEVELS.block) totals.level = LEVELS.block;
  else if (r.level === LEVELS.mask && totals.level === LEVELS.pass) totals.level = LEVELS.mask;
}

/**
 * 拦截一个已解析的 RPC payload / Intercept one parsed RPC payload.
 *
 * @param {string} endpoint RPC endpoint，如 `session/prompt`
 * @param {unknown} payload 已解析的请求体 / parsed payload
 * @param {object[]} rules
 * @param {(sessionId: string) => object} contextFor
 * @param {(line: string) => void} log
 * @param {{diagnose?: boolean}} [options]
 * @returns {{handled: boolean, payload?: unknown, level?: string, counts?: object, kinds?: Set<string>}}
 */
export function interceptPayload(endpoint, payload, rules, contextFor, log, options = {}) {
  const method = typeof endpoint === 'string' ? endpoint : '?';

  if (options.diagnose === true) {
    const shape = payload !== null && typeof payload === 'object' ? Object.keys(payload).join(',') : typeof payload;
    log(`sensitive-guard 【诊断】RPC 拦截 endpoint=${method} keys=${shape}`);
  }

  if (!isPromptEndpoint(endpoint)) return { handled: false };

  // 含附件容器？用原地脱敏（只改 text 字段，保持对象身份，附件不受影响）。
  // 纯文本消息走常规 sanitizeArgs（可重建，无附件引用风险）。
  const hasAttachment = (() => {
    const walk = (v, depth) => {
      if (depth > 8 || v === null || typeof v !== 'object') return false;
      if (Array.isArray(v)) return v.some((x) => walk(x, depth + 1));
      if (isAttachmentContainer(v, '') || v.type === 'image') return true;
      return Object.entries(v).some(([k, x]) => (k === 'attachment' || k === 'attachments') || walk(x, depth + 1));
    };
    return walk(payload, 0);
  })();

  try {
    const sessionId = payload?.sessionId ?? payload?.session ?? payload?.args?.sessionId ?? 'default';
    const context = contextFor(sessionId);

    if (hasAttachment) {
      // 重建对象树但 image 块复用原引用：文字脱敏生效，附件身份不变。
      const result = sanitizeWithAttachments(payload, rules, context);
      if (!result.changed) return { handled: false };
      log(`sensitive-guard ${structuredLog(result, 'rpc_pre_inbox_image', inputHash(JSON.stringify(payload)))}`);
      log(`sensitive-guard 【✅图文混合：文字已脱敏，附件原样保留】level=${result.level}`);
      return { handled: true, payload: result.value, level: result.level, counts: result.counts, kinds: result.kinds };
    }

    const result = sanitizeArgs(payload, rules, context);
    if (!result.changed) {
      if (options.diagnose === true) {
        log(`sensitive-guard 【诊断】prompt 端点无敏感内容 endpoint=${method}`);
      }
      return { handled: false };
    }

    log(`sensitive-guard ${structuredLog(
      { level: result.level, kinds: result.kinds, hits: result.hits, counts: result.counts },
      'rpc_pre_inbox',
      inputHash(JSON.stringify(payload)),
    )}`);
    log(`sensitive-guard 【✅请求体已前置清洗】endpoint=${method} level=${result.level}，明文未进入 inbox`);
    return { handled: true, payload: result.value, level: result.level, counts: result.counts, kinds: result.kinds };
  } catch (error) {
    log(`sensitive-guard 【⚠️前置清洗异常】${error?.message ?? 'unknown'}，原样放行`);
    return { handled: false };
  }
}

/**
 * 读完整请求体（保留给旧 HTTP 路径）/ Read a full request body.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<Buffer | undefined>}
 */
export async function readBody(req) {
  const MAX_BODY_BYTES = 300 * 1024 * 1024;
  const declared = Number(req.headers['content-length'] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return undefined;
  const chunks = [];
  let received = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += buffer.byteLength;
    if (received > MAX_BODY_BYTES) return undefined;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * 原地替换请求体（保留给旧 HTTP 路径）/ Replace a request body in place.
 * @param {import('node:http').IncomingMessage} req
 * @param {Buffer} body
 */
export function replaceRequestBody(req, body) {
  const headers = { ...req.headers, 'content-length': String(body.byteLength) };
  for (const key of Object.keys(req.headers)) delete req.headers[key];
  Object.assign(req.headers, headers);

  let consumed = false;
  req[Symbol.asyncIterator] = async function* replay() {
    if (consumed) return;
    consumed = true;
    yield body;
  };
  req.readableEnded = false;
  req.complete = false;
}

/**
 * 旧 HTTP 层拦截（保留以兼容真实 HTTP 部署）/ Legacy HTTP-layer interception.
 * @param {import('node:http').IncomingMessage} req
 * @param {object[]} rules
 * @param {(sessionId: string) => object} contextFor
 * @param {(line: string) => void} log
 * @param {{diagnose?: boolean}} [options]
 */
export async function interceptPromptBody(req, rules, contextFor, log, options = {}) {
  const method = String(req.method ?? '').toUpperCase();
  if (options.diagnose === true) {
    log(`sensitive-guard 【诊断】HTTP connection/request method=${method} url=${req.url ?? '?'}`);
  }
  if (method !== 'POST') return { handled: false };

  let body;
  try {
    body = await readBody(req);
  } catch {
    return { handled: false };
  }
  if (body === undefined) return { handled: false };

  let payload;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    return { handled: false, replay: body };
  }

  if (!isPromptEnvelope(payload)) return { handled: false, replay: body };

  try {
    const sessionId = payload?.args?.sessionId ?? payload?.args?.session ?? 'default';
    const context = contextFor(sessionId);
    const result = sanitizeArgs(payload.args, rules, context);
    if (!result.changed) return { handled: false, replay: body };

    payload.args = result.value;
    const nextBody = Buffer.from(JSON.stringify(payload), 'utf8');
    log(`sensitive-guard 【✅HTTP前置清洗】level=${result.level}`);
    return { handled: true, replay: nextBody, level: result.level, counts: result.counts, kinds: result.kinds };
  } catch (error) {
    log(`sensitive-guard 【⚠️HTTP前置清洗异常】${error?.message ?? 'unknown'}，原样放行`);
    return { handled: false, replay: body };
  }
}
