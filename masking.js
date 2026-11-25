/**
 * 脱敏引擎 / Masking engine.
 *
 * 本文件实现「怎么替换」，不关心挂载点与图片。
 * This module implements how replacement happens; hook points and images live
 * elsewhere.
 *
 * 三条硬约束 / Three hard invariants:
 *
 * 1. 只做单次正向替换，原始明文不落盘、不还原、不进日志。
 *    Single forward pass; plaintext is never stored, restored, or logged.
 * 2. 占位符一经写入，后续规则不再匹配，同一个值只替换一次。
 *    A written placeholder is never re-matched, so a value is masked once.
 * 3. 白名单优先于一切规则。
 *    The whitelist outranks every rule.
 */

import { createHash } from 'node:crypto';
import { buildRules, isExcluded, luhn } from './rules.js';

const MAX_SCAN_CHARS = 4 * 1024 * 1024;
const MAX_REGISTRY_ENTRIES = 512;

/**
 * 会话级占位符注册表 / Per-session placeholder registry.
 *
 * 同一个值在同一会话内恒定得到同一个占位符，保证上下文不错乱。
 * 注册表只存 SHA-256 摘要，不存明文。
 *
 * The same value always maps to the same placeholder within one session, so the
 * model's context stays coherent. Only a digest is retained, never the value.
 */
export function createRegistry() {
  const entries = new Map();
  const counters = new Map();
  return {
    /**
     * @param {string} category 占位符基名 / placeholder base text
     * @param {string} value 命中值，仅用于摘要 / matched value, used for the digest only
     * @returns {string} 本会话内该值的稳定占位符 / stable placeholder
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

/**
 * 判断是否白名单 / Whitelist test.
 *
 * 规格要求「命中白名单，跳过匹配，不标记、不脱敏」，因此这里同时用于
 * 规则匹配阶段与高熵兜底阶段。
 */
export function isWhitelisted(value, config) {
  const list = config.whitelist ?? [];
  const lowered = String(value).toLowerCase();
  return list.some((token) => lowered.includes(String(token).toLowerCase()));
}

/**
 * 脱敏单个字符串 / Mask one string.
 *
 * @param {string} text
 * @param {object[]} rules 规则表 / rule table
 * @param {{config: object, registry: object, sessionWhitelist?: Set<string>}} context
 * @returns {{text: string, counts: Record<string, number>, risk?: 'high'|'normal', kinds: Set<string>}}
 */
export function maskText(text, rules, context) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text, counts: {}, risk: undefined, kinds: new Set() };
  }
  if (text.length > MAX_SCAN_CHARS) {
    return { text, counts: {}, risk: undefined, kinds: new Set() };
  }

  let next = text;
  const counts = {};
  const kinds = new Set();
  let risk;

  for (const rule of rules) {
    next = next.replace(rule.re, (...args) => {
      const whole = args[0];
      if (typeof whole !== 'string') return whole;

      // 已经写过的占位符不再参与匹配，避免二次替换产生 _2 变体。
      if (whole.includes('{{')) return whole;

      if (rule.validate && !rule.validate(whole)) return whole;

      // 白名单判定的是「被替换的那个值」，不是整段匹配。
      // 带 keepGroup 的规则里，第 1 组是前缀（键名+分隔符），第 2 组才是取值。
      //
      // The whitelist judges the replaced value, not the whole match. For a
      // keepGroup rule, group 1 is the prefix and group 2 is the value.
      const value = rule.keepGroup !== undefined
        ? String(args[rule.keepGroup + 1] ?? args[rule.keepGroup] ?? whole)
        : whole;
      const valueBody = rule.keepGroup !== undefined
        ? value.replace(/^[\s\S]*?[:=：]\s*["'`]?/, '')
        : value;

      if (isWhitelisted(value, context.config) || isWhitelisted(valueBody, context.config)) return whole;

      // 会话临时白名单：用户标记过的误判内容，当前会话不再脱敏。
      if (context.sessionWhitelist?.has(valueBody) || context.sessionWhitelist?.has(whole)) return whole;

      // 排除项（端口、版本号、哈希）不判为凭证。
      if (rule.id === 'high-entropy' && isExcluded(whole)) return whole;

      const placeholder = context.registry.placeholderFor(rule.to, value);
      counts[placeholder] = (counts[placeholder] ?? 0) + 1;
      kinds.add(rule.kind ?? '其他');
      if (rule.risk === 'high') risk = 'high';
      else if (risk === undefined) risk = 'normal';

      if (rule.keepGroup !== undefined) {
        return `${args[rule.keepGroup]}${placeholder}`;
      }
      return placeholder;
    });
  }

  return { text: next, counts, risk, kinds };
}

/**
 * 脱敏内容块数组 / Mask the text blocks of a content array.
 *
 * 只处理 `text` 块；`image`、`file`、`tool-call` 的结构原样保留。
 * Only text blocks are touched; image, file, and tool-call blocks keep their
 * structure.
 */
export function maskContent(content, rules, context) {
  if (!Array.isArray(content)) return { content, counts: {}, risk: undefined, kinds: new Set() };
  let changed = false;
  const counts = {};
  const kinds = new Set();
  let risk;
  const next = content.map((block) => {
    if (!block || block.type !== 'text' || typeof block.text !== 'string') return block;
    const masked = maskText(block.text, rules, context);
    if (masked.text === block.text) return block;
    changed = true;
    for (const [placeholder, count] of Object.entries(masked.counts)) {
      counts[placeholder] = (counts[placeholder] ?? 0) + count;
    }
    for (const kind of masked.kinds) kinds.add(kind);
    if (masked.risk === 'high') risk = 'high';
    else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
    return { ...block, text: masked.text };
  });
  return { content: changed ? next : content, counts, risk, kinds };
}

/**
 * 递归脱敏 JSON 值 / Mask a JSON value recursively.
 *
 * 规格要求「JSON 只替换 value 值，保留 key 字段名称」。键名一律不动，
 * 只对字符串叶子节点做替换，因此结构恒为合法 JSON。
 */
export function maskValue(value, rules, context, depth = 0) {
  if (depth > 12) return { value, counts: {}, risk: undefined, kinds: new Set() };
  if (typeof value === 'string') {
    // 字符串分支要把 `text` 归一成 `value`，否则上层拿到的是 undefined。
    // The string branch normalizes `text` to `value`; otherwise callers see
    // undefined and an array would collapse into nulls.
    const masked = maskText(value, rules, context);
    return { value: masked.text, counts: masked.counts, risk: masked.risk, kinds: masked.kinds };
  }
  if (Array.isArray(value)) {
    const counts = {};
    const kinds = new Set();
    let risk;
    let changed = false;
    const next = value.map((item) => {
      const masked = maskValue(item, rules, context, depth + 1);
      if (masked.value !== item) changed = true;
      for (const [placeholder, count] of Object.entries(masked.counts)) {
        counts[placeholder] = (counts[placeholder] ?? 0) + count;
      }
      for (const kind of masked.kinds) kinds.add(kind);
      if (masked.risk === 'high') risk = 'high';
      else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
      return masked.value;
    });
    return { value: changed ? next : value, counts, risk, kinds };
  }
  if (value !== null && typeof value === 'object') {
    const counts = {};
    const kinds = new Set();
    let risk;
    let changed = false;
    const next = {};
    for (const [key, item] of Object.entries(value)) {
      const masked = maskValue(item, rules, context, depth + 1);
      if (masked.value !== item) changed = true;
      for (const [placeholder, count] of Object.entries(masked.counts)) {
        counts[placeholder] = (counts[placeholder] ?? 0) + count;
      }
      for (const kind of masked.kinds) kinds.add(kind);
      if (masked.risk === 'high') risk = 'high';
      else if (masked.risk === 'normal' && risk === undefined) risk = 'normal';
      next[key] = masked.value;
    }
    return { value: changed ? next : value, counts, risk, kinds };
  }
  return { value, counts: {}, risk: undefined, kinds: new Set() };
}

/**
 * 审计一个即将发出的请求 / Audit one outgoing request.
 *
 * 只读：Agent 循环构建的请求是深冻结的，这里只统计残余命中，绝不改写。
 * Read-only: a loop-built request is deep-frozen, so this counts residual hits
 * and never rewrites.
 */
export function auditRequest(options, rules, context) {
  const counts = {};
  const kinds = new Set();
  let risk;
  let images = 0;

  const absorb = (result) => {
    for (const [placeholder, count] of Object.entries(result.counts)) {
      counts[placeholder] = (counts[placeholder] ?? 0) + count;
    }
    for (const kind of result.kinds) kinds.add(kind);
    if (result.risk === 'high') risk = 'high';
    else if (result.risk === 'normal' && risk === undefined) risk = 'normal';
  };

  if (typeof options?.system === 'string') absorb(maskText(options.system, rules, context));
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
  return { counts, risk, kinds, images };
}

export { buildRules, luhn };
