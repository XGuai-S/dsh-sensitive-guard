/**
 * 分级扫描引擎 / Leveled scanning engine.
 *
 * 本文件实现「怎么扫描」与「怎么分级」，不关心挂载点。
 * This module implements how scanning and grading work; hook points live
 * elsewhere.
 *
 * 三条硬约束 / Three hard invariants:
 *
 * 1. 只做单次正向替换，原始明文不落盘、不还原、不进日志。
 *    Single forward pass; plaintext is never stored, restored, or logged.
 * 2. 占位符一经写入，后续规则不再匹配，同一个值只替换一次。
 * 3. 白名单优先级最高，命中即跳过所有规则。
 *
 * 新增能力 / Added capabilities:
 *
 * - **分片扫描**：超过 `CHUNK_SIZE` 的文本按边界切分，避免正则在大文本上回溯爆炸。
 * - **递归扫描**：嵌套 JSON 与一层 base64 自动解码，深度上限 3 层。
 * - **二次复检**：脱敏结果再扫一遍，仍有 BLOCK 则升级为阻断。
 * - **结构化日志**：固定字段 time/source/level/hitType/ruleId/inputHash，
 *   `hitText` 只存掩码预览，不存原文。
 */

import { createHash } from 'node:crypto';
import {
  buildRules, isExcluded, luhn, isWhitelistedValue, isHighEntropy,
  LEVELS, HIT_KINDS, CHUNK_SIZE, MAX_RECURSE_DEPTH, MAX_SCAN_CHARS,
} from './rules.js';

const MAX_REGISTRY_ENTRIES = 512;

/**
 * 会话级占位符注册表 / Per-session placeholder registry.
 *
 * 同一个值在同一会话内恒定得到同一个占位符，保证上下文不错乱。
 * 注册表只存 SHA-256 摘要，不存明文。
 */
export function createRegistry() {
  const entries = new Map();
  const counters = new Map();
  return {
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

/**
 * 掩码预览 / Masked preview for logs.
 *
 * 规格要求日志含 hitText，但同时禁止存储原文。折中方案：只保留前 3 个字符与
 * 总长度，足以定位是哪一类内容，不足以复原。
 *
 * The spec asks for a hitText log field while also forbidding plaintext. This
 * keeps the first three characters and the length: enough to identify the kind
 * of value, not enough to reconstruct it.
 */
export function maskPreview(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  if (value.length <= 3) return '*'.repeat(value.length);
  return `${value.slice(0, 3)}***(${value.length})`;
}

/**
 * 输入摘要 / Digest of one scanned input.
 * 用于关联同一段文本的多次扫描，不暴露内容。
 */
export function inputHash(text) {
  if (typeof text !== 'string' || text.length === 0) return '';
  return createHash('sha256').update(text).digest('hex').slice(0, 16);
}

/**
 * 按边界切分超长文本 / Split oversized text at safe boundaries.
 *
 * 优先在换行、句号、逗号处切开，避免把一个敏感值拦腰截断。
 * Prefers newlines and sentence punctuation so a value is not cut in half.
 */
export function chunkText(text, size = CHUNK_SIZE) {
  if (typeof text !== 'string') return [];
  if (text.length <= size) return [text];
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + size, text.length);
    if (end < text.length) {
      // 从 end 往回找最近的边界，最多回退 256 字符。
      const window = text.slice(Math.max(start, end - 256), end);
      const match = /[\n。；;，,]\s*(?![\s\S]*[\n。；;，,])/.exec(window);
      if (match) end = Math.max(start, end - 256) + match.index + match[0].length;
    }
    chunks.push(text.slice(start, end));
    start = end;
  }
  return chunks;
}

/**
 * 扫描一段文本并按级别汇总 / Scan one string and aggregate its level.
 *
 * 分片只用于「控制单次正则的输入规模」，不用于「先切后扫」：切分会把一个
 * 敏感值拦腰截断，导致漏检。因此先在完整文本上跑一遍检测（不替换），
 * 只有确认存在命中、且文本确实超长时，才逐片替换。
 *
 * Chunking bounds the regex input size; it must not cut a value in half and
 * cause a miss. Detection therefore runs once over the whole text, and only a
 * confirmed hit on oversized input falls back to per-chunk replacement.
 *
 * @param {string} text
 * @param {object[]} rules
 * @param {{config: object, registry: object, sessionWhitelist?: Set<string>}} context
 * @returns {{text: string, level: string, counts: object, kinds: Set<string>,
 *   hits: object[], whitelisted: boolean, changed: boolean}}
 */
export function scanText(text, rules, context) {
  const empty = { text, level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], whitelisted: false, changed: false };
  if (typeof text !== 'string' || text.length === 0) return empty;
  if (text.length > MAX_SCAN_CHARS) {
    // 超大文本整体判定为可疑，交由调用方决定。
    return { ...empty, level: LEVELS.block, hits: [{ ruleId: 'oversized-input', kind: '超大文本' }] };
  }

  // 白名单优先：整段命中即放行，不做任何替换。
  if (isWhitelistedValue(text)) return { ...empty, whitelisted: true };

  // 短文本直接扫。
  if (text.length <= CHUNK_SIZE) return scanChunk(text, rules, context);

  // 长文本：先在完整文本上检测，避免分片切断敏感值。
  const probe = scanChunk(text, rules, context);
  if (probe.level === LEVELS.pass) return probe;

  // 确认有命中，逐片替换后拼接，保证结果完整。
  const merged = { text: '', level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], whitelisted: false, changed: false };
  for (const chunk of chunkText(text)) {
    const result = scanChunk(chunk, rules, context);
    merged.text += result.text;
    merged.changed = merged.changed || result.changed;
    for (const [placeholder, count] of Object.entries(result.counts)) {
      merged.counts[placeholder] = (merged.counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds) merged.kinds.add(kind);
    merged.hits.push(...result.hits);
    if (result.level === LEVELS.block) merged.level = LEVELS.block;
    else if (result.level === LEVELS.mask && merged.level === LEVELS.pass) merged.level = LEVELS.mask;
  }
  // 分片替换若漏掉了跨越边界的值，用整体扫描的结论兜底。
  if (merged.level === LEVELS.pass) return probe;
  return merged;
}

/**
 * 扫描单个分片 / Scan one chunk.
 * 这是规则匹配的核心循环。
 */
function scanChunk(text, rules, context) {
  let next = text;
  const counts = {};
  const kinds = new Set();
  const hits = [];
  let level = LEVELS.pass;
  let changed = false;

  for (const rule of rules) {
    if (context.config?.disabledRules?.includes(rule.id)) continue;
    next = next.replace(rule.re, (...args) => {
      const whole = args[0];
      if (typeof whole !== 'string') return whole;

      // 已写入的占位符不再参与匹配，避免二次替换。
      if (whole.includes('{{')) return whole;

      if (rule.validate && !rule.validate(whole)) return whole;

      // 白名单判定对象是「被替换的值」，不是整段匹配。
      const value = rule.keepGroup !== undefined
        ? String(args[rule.keepGroup + 1] ?? args[rule.keepGroup] ?? whole)
        : whole;
      const valueBody = rule.keepGroup !== undefined
        ? value.replace(/^[\s\S]*?[:=：]\s*["'`]?/, '')
        : value;

      if (isWhitelistedValue(value) || isWhitelistedValue(valueBody)) return whole;
      if (context.sessionWhitelist?.has(valueBody) || context.sessionWhitelist?.has(whole)) return whole;
      if (rule.id === 'high-entropy' && isExcluded(whole)) return whole;

      const target = typeof rule.toFor === 'function' ? rule.toFor(whole) : rule.to;
      const placeholder = context.registry.placeholderFor(target, value);

      counts[placeholder] = (counts[placeholder] ?? 0) + 1;
      kinds.add(rule.kind ?? '其他');
      hits.push({
        ruleId: rule.id,
        kind: rule.kind ?? '其他',
        level: rule.level,
        placeholder,
        preview: maskPreview(valueBody),
      });
      changed = true;

      if (rule.level === LEVELS.block) level = LEVELS.block;
      else if (rule.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;

      if (rule.keepGroup !== undefined) {
        return `${args[rule.keepGroup]}${placeholder}`;
      }
      return placeholder;
    });
  }

  return { text: next, level, counts, kinds, hits, whitelisted: false, changed };
}

/**
 * 递归扫描嵌套内容 / Scan nested content recursively.
 *
 * 处理三种嵌套：JSON 对象/数组、一层 base64 串、URL 编码串。
 * 深度上限 `MAX_RECURSE_DEPTH`，防止死循环。
 */
export function scanDeep(text, rules, context, depth = 0) {
  const base = scanText(text, rules, context);
  if (depth >= MAX_RECURSE_DEPTH) return base;
  if (typeof text !== 'string' || text.length === 0) return base;

  let level = base.level;
  const counts = { ...base.counts };
  const kinds = new Set(base.kinds);
  const hits = [...base.hits];
  let merged = base.text;

  const absorb = (result) => {
    for (const [placeholder, count] of Object.entries(result.counts)) {
      counts[placeholder] = (counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds) kinds.add(kind);
    hits.push(...result.hits);
    if (result.level === LEVELS.block) level = LEVELS.block;
    else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
  };

  // 一层 base64：解码后若命中，整串替换。
  //
  // 阈值取 24：更短的 base64 解码后没有足够内容承载一个凭据。
  // 判定要求**解码结果自身命中具体规则**，而不是「解码成功就算可疑」：
  // `aGVsbG8gd29ybGQ=` 这类普通文本载荷必须放行。
  //
  // A hit requires the decoded text to match a concrete rule; a successful
  // decode is not itself suspicious, or ordinary text payloads would be masked.
  if (context.config?.detectBase64 === true) {
    merged = merged.replace(/[A-Za-z0-9+/]{24,}={0,2}/g, (run) => {
      let decoded;
      try {
        decoded = Buffer.from(run, 'base64').toString('utf8');
      } catch {
        return run;
      }
      // 回编码校验：不是合法 base64 的串会在这里被排除。
      // Round-trip check rejects anything that was not really base64.
      if (Buffer.from(decoded, 'utf8').toString('base64').replace(/=+$/, '') !== run.replace(/=+$/, '')) return run;
      // 解码结果必须可打印，否则这不是文本载荷。
      if (!decoded || /[\u0000-\u0008\u000e-\u001f]/.test(decoded)) return run;
      if (!/[\x20-\x7e\u4e00-\u9fff]{8,}/.test(decoded)) return run;
      const inner = scanDeep(decoded, rules, context, depth + 1);
      if (inner.level === LEVELS.pass) return run;
      absorb(inner);
      return '{{SECRET_TOKEN}}';
    });
  }

  // 嵌套 JSON：解析后递归扫描字符串叶子。
  const trimmed = merged.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed = JSON.parse(trimmed);
      const masked = scanValue(parsed, rules, context, depth + 1);
      absorb(masked);
      if (masked.changed) merged = JSON.stringify(masked.value);
    } catch {
      // 不是合法 JSON，按普通文本处理。
    }
  }

  return {
    text: merged,
    level,
    counts,
    kinds,
    hits,
    whitelisted: base.whitelisted,
    changed: base.changed || merged !== text,
  };
}

/**
 * 递归扫描 JSON 值 / Scan a JSON value recursively.
 * 只替换 value，保留 key，保证结构合法。
 */
export function scanValue(value, rules, context, depth = 0) {
  if (depth > MAX_RECURSE_DEPTH) {
    return { value, level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], changed: false };
  }
  if (typeof value === 'string') {
    const result = scanDeep(value, rules, context, depth);
    return { value: result.text, level: result.level, counts: result.counts, kinds: result.kinds, hits: result.hits, changed: result.changed };
  }
  if (Array.isArray(value)) {
    const counts = {};
    const kinds = new Set();
    const hits = [];
    let level = LEVELS.pass;
    let changed = false;
    const next = value.map((item) => {
      const result = scanValue(item, rules, context, depth + 1);
      if (result.value !== item) changed = true;
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
    const counts = {};
    const kinds = new Set();
    const hits = [];
    let level = LEVELS.pass;
    let changed = false;
    const next = {};
    for (const [key, item] of Object.entries(value)) {
      const result = scanValue(item, rules, context, depth + 1);
      if (result.value !== item) changed = true;
      for (const [placeholder, count] of Object.entries(result.counts)) {
        counts[placeholder] = (counts[placeholder] ?? 0) + count;
      }
      for (const kind of result.kinds) kinds.add(kind);
      hits.push(...result.hits);
      if (result.level === LEVELS.block) level = LEVELS.block;
      else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
      next[key] = result.value;
    }
    return { value: changed ? next : value, level, counts, kinds, hits, changed };
  }
  return { value, level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], changed: false };
}

/**
 * 完整扫描 + 二次复检 / Full scan with re-check.
 *
 * 三种结果 / Three outcomes:
 *
 * - **BLOCK**：返回**清洗后**的 `content`，敏感片段已被占位符替换。
 *   调用方据此继续执行，不阻断任务。
 * - **MASK**：返回替换后的 `content`。
 * - **PASS**：返回原文。
 *
 * BLOCK 与 MASK 都会做二次复检：清洗结果再扫一遍，若仍有阻断级残留，
 * 再清洗一轮（`passes` 记录轮次），最多 3 轮，避免死循环。
 *
 * BLOCK returns the *cleaned* text with sensitive spans already replaced, so
 * the caller can continue instead of aborting. Both BLOCK and MASK are
 * re-checked; a residual block triggers another cleaning pass, at most three.
 *
 * @param {string} text
 * @param {object[]} rules
 * @param {{config: object, registry: object, sessionWhitelist?: Set<string>}} context
 * @param {{recheck?: boolean, source?: string}} options
 * @returns {{level: string, content: string, counts: object, kinds: Set<string>,
 *   hits: object[], whitelisted: boolean, rechecked: boolean, passes: number,
 *   cleaned: boolean}}
 */
export function runSanitize(text, rules, context, options = {}) {
  const first = scanDeep(text, rules, context);

  if (first.whitelisted) {
    return { level: LEVELS.pass, content: text, counts: {}, kinds: new Set(), hits: [], whitelisted: true, rechecked: false, passes: 0, cleaned: false };
  }
  if (first.level === LEVELS.pass) {
    return { level: LEVELS.pass, content: text, counts: {}, kinds: new Set(), hits: [], whitelisted: false, rechecked: false, passes: 0, cleaned: false };
  }

  // BLOCK 与 MASK 都返回清洗后的内容，区别只在 level 标签与日志等级。
  const recheck = options.recheck !== false;
  const maxPasses = 3;
  let current = first;
  let passes = 1;
  let rechecked = false;

  if (recheck) {
    // 复检清洗结果；仍有阻断级残留则再清洗一轮。
    while (passes < maxPasses) {
      const second = scanText(current.text, rules, context);
      rechecked = true;
      if (second.level === LEVELS.pass) break;
      // 清洗后仍是 BLOCK：说明上一轮有跨规则残留，继续清洗。
      if (second.level === LEVELS.block) {
        passes += 1;
        current = {
          ...second,
          counts: { ...current.counts, ...second.counts },
          kinds: new Set([...current.kinds, ...second.kinds]),
          hits: [...current.hits, ...second.hits],
        };
        continue;
      }
      // 复检降为 MASK：合并统计后结束。
      current = {
        ...current,
        counts: { ...current.counts, ...second.counts },
        kinds: new Set([...current.kinds, ...second.kinds]),
        hits: [...current.hits, ...second.hits],
      };
      break;
    }
  }

  return {
    level: first.level,
    content: current.text,
    counts: current.counts,
    kinds: current.kinds,
    hits: current.hits,
    whitelisted: false,
    rechecked,
    passes,
    cleaned: current.text !== text,
  };
}


/**
 * 扫描内容块数组 / Scan a content-block array.
 * 只处理 text 块，其余块结构原样保留。
 */
export function scanContent(content, rules, context) {
  if (!Array.isArray(content)) {
    return { content, level: LEVELS.pass, counts: {}, kinds: new Set(), hits: [], changed: false };
  }
  let changed = false;
  let level = LEVELS.pass;
  const counts = {};
  const kinds = new Set();
  const hits = [];
  const next = content.map((block) => {
    if (!block || block.type !== 'text' || typeof block.text !== 'string') return block;
    const result = runSanitize(block.text, rules, context);
    if (result.content === block.text && result.level === LEVELS.pass) return block;
    changed = true;
    for (const [placeholder, count] of Object.entries(result.counts)) {
      counts[placeholder] = (counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds) kinds.add(kind);
    hits.push(...result.hits);
    if (result.level === LEVELS.block) level = LEVELS.block;
    else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
    return { ...block, text: result.content };
  });
  return { content: changed ? next : content, level, counts, kinds, hits, changed };
}

/**
 * 扫描一个请求 / Scan an outgoing request.
 * 只读：循环构建的请求是深冻结的，这里只统计，不改写。
 */
export function auditRequest(options, rules, context) {
  const counts = {};
  const kinds = new Set();
  const hits = [];
  let level = LEVELS.pass;
  let images = 0;

  const absorb = (result) => {
    for (const [placeholder, count] of Object.entries(result.counts)) {
      counts[placeholder] = (counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds) kinds.add(kind);
    hits.push(...result.hits);
    if (result.level === LEVELS.block) level = LEVELS.block;
    else if (result.level === LEVELS.mask && level === LEVELS.pass) level = LEVELS.mask;
  };

  if (typeof options?.system === 'string') absorb(scanText(options.system, rules, context));
  for (const message of options?.messages ?? []) {
    if (typeof message?.content === 'string') {
      absorb(scanText(message.content, rules, context));
      continue;
    }
    for (const block of message?.content ?? []) {
      if (block?.type === 'text') absorb(scanText(block.text, rules, context));
      else if (block?.type === 'tool-call') absorb(scanText(block.arguments, rules, context));
      else if (block?.type === 'image') images += 1;
    }
  }
  return { level, counts, kinds, hits, images };
}

/**
 * 构建结构化日志行 / Build one structured log line.
 *
 * 固定字段：time、source、level、hitType、hitText、ruleId、inputHash。
 * `hitText` 只存掩码预览，不存原文。
 *
 * Fixed fields as specified. `hitText` carries a masked preview only.
 */
export function structuredLog(result, source, digest) {
  const kinds = result.kinds && result.kinds.size > 0 ? [...result.kinds].join('/') : '-';
  const top = result.hits?.[0];
  const counts = Object.entries(result.counts ?? {}).map(([p, c]) => `${p}×${c}`).join(' ');
  return JSON.stringify({
    time: new Date().toISOString(),
    source,
    level: result.level,
    hitType: kinds,
    hitText: top?.preview ?? '',
    ruleId: top?.ruleId ?? '',
    inputHash: digest ?? '',
    counts,
  });
}

export { buildRules, luhn, isExcluded, isWhitelistedValue, isHighEntropy, HIT_KINDS, LEVELS };
