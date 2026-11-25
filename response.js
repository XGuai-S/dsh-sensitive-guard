/**
 * 响应侧扫描 / Response-side scanning.
 *
 * 为什么可行 / Why this works:
 *
 * `BlockAssembler.push` 对 `block-end` 的处理是 `partial.block = chunk.block`，
 * 一旦某个块有了 `block`，`assemble()` 就直接返回它，忽略此前累积的
 * `text-delta`。所以在块闭合时发一个改写的 `block-end`，就能让下游拿到
 * 清洗后的内容。
 *
 * `BlockAssembler.push` assigns `partial.block = chunk.block` on `block-end`,
 * and `assemble()` then returns that block instead of the accumulated deltas.
 *
 * 处置原则 / Disposition:
 *
 * 只清洗、不中断。BLOCK 与 MASK 都下发清洗后的文本，区别只在日志等级；
 * PASS 原样下发。模型输出永远不会被截断。
 *
 * Clean, never truncate. Both BLOCK and MASK emit the cleaned text; only the
 * log level differs. PASS passes through unchanged.
 *
 * 限制 / Limits:
 *
 * 改写发生在一个块结束时，因此模型侧的增量渲染可能已显示过原文；
 * 本插件保证的是「进入会话日志与后续请求的内容」已处理。
 */

import { runSanitize, scanText } from './masking.js';
import { LEVELS } from './rules.js';

/**
 * 包装一条流，对已闭合的文本块做分级扫描。
 *
 * @param {AsyncIterable<object>} stream 原始流
 * @param {object[]} rules 规则表
 * @param {{config: object, registry: object, sessionWhitelist?: Set<string>}} context
 * @param {(result: object) => void} onResult 命中回调，用于记录日志
 * @returns {AsyncIterable<object>} 处理后的流
 */
export async function* maskResponseStream(stream, rules, context, onResult) {
  const pending = new Map();

  for await (const chunk of stream) {
    if (chunk?.type === 'block-start') {
      pending.set(chunk.index, { blockType: chunk.blockType, text: '' });
      yield chunk;
      continue;
    }

    if (chunk?.type === 'text-delta' || chunk?.type === 'reasoning-delta') {
      const entry = pending.get(chunk.index);
      if (entry !== undefined) entry.text += chunk.text;
      yield chunk;
      continue;
    }

    if (chunk?.type === 'block-end') {
      const block = chunk.block;
      if ((block?.type === 'text' || block?.type === 'reasoning') && typeof block.text === 'string') {
        const result = runSanitize(block.text, rules, context);

        // BLOCK 与 MASK 都下发清洗后的内容，区别只在日志等级。
        if (result.level !== LEVELS.pass) {
          onResult?.(result);
          pending.delete(chunk.index);
          yield { ...chunk, block: { ...block, text: result.content } };
          continue;
        }
      }
      pending.delete(chunk.index);
      yield chunk;
      continue;
    }

    // tool-call-delta 与 usage 原样透传。
    yield chunk;
  }
}

/**
 * 解码并扫描 base64 串 / Decode and scan base64 runs.
 *
 * 可选能力：模型可能把凭据编成 base64 输出，纯文本规则看不见。
 *
 * @param {string} text
 * @param {object[]} rules
 * @param {object} context
 * @returns {{text: string, level: string, hit: boolean}}
 */
export function maskBase64Payloads(text, rules, context) {
  if (typeof text !== 'string' || text.length < 24) return { text, level: LEVELS.pass, hit: false };
  let hit = false;
  let level = LEVELS.pass;
  const next = text.replace(/[A-Za-z0-9+/]{24,}={0,2}/g, (run) => {
    let decoded;
    try {
      decoded = Buffer.from(run, 'base64').toString('utf8');
    } catch {
      return run;
    }
    if (!decoded || /[\u0000-\u0008\u000e-\u001f]/.test(decoded)) return run;
    if (!/[\x20-\x7e\u4e00-\u9fff]{8,}/.test(decoded)) return run;
    const inner = scanText(decoded, rules, context);
    if (inner.level === LEVELS.pass) return run;
    hit = true;
    if (inner.level === LEVELS.block) level = LEVELS.block;
    else if (level === LEVELS.pass) level = LEVELS.mask;
    return '{{SECRET_TOKEN}}';
  });
  return { text: next, level, hit };
}
