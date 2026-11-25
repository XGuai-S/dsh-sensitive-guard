/**
 * 响应侧脱敏 / Response-side masking.
 *
 * 为什么可行 / Why this works:
 *
 * `BlockAssembler.push` 对 `block-end` 的处理是 `partial.block = chunk.block`，
 * 一旦某个块有了 `block`，`assemble()` 就直接返回它，忽略此前累积的
 * `text-delta`。所以只要在流式返回途中，把整块文本拼好后用 `block-end`
 * 覆盖一次，就能让下游拿到脱敏后的内容，而不必改动已发出的事件。
 *
 * `BlockAssembler.push` assigns `partial.block = chunk.block` on `block-end`,
 * and `assemble()` then returns that block instead of the accumulated deltas.
 * Emitting a rewritten `block-end` therefore replaces the block downstream,
 * without touching deltas that were already delivered.
 *
 * 限制 / Limits:
 *
 * - 只能覆盖「已闭合的整块」。跨块边界的敏感值无法识别，因为块与块之间
 *   没有语义关联。
 * - 改写发生在一个块结束时，因此模型侧的增量渲染可能已经显示过原文；
 *   本插件保证的是「进入会话日志与后续请求的内容」已脱敏。
 */

import { maskText } from './masking.js';

/**
 * 包装一条流，对已闭合的文本/推理块做脱敏。
 *
 * @param {AsyncIterable<object>} stream 原始流 / the adapter stream
 * @param {object[]} rules 规则表 / rule table
 * @param {{config: object, registry: object, sessionWhitelist?: Set<string>}} context
 * @param {(result: {counts: object, risk?: string, kinds: Set<string>}) => void} onMask
 *   命中回调，用于记录日志；不传则不记录。
 * @returns {AsyncIterable<object>} 脱敏后的流 / the masked stream
 */
export async function* maskResponseStream(stream, rules, context, onMask) {
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
      if (block?.type === 'text' && typeof block.text === 'string') {
        const masked = maskText(block.text, rules, context);
        if (masked.text !== block.text) {
          onMask?.(masked);
          yield { ...chunk, block: { ...block, text: masked.text } };
          pending.delete(chunk.index);
          continue;
        }
      } else if (block?.type === 'reasoning' && typeof block.text === 'string') {
        // 推理过程同样可能复述凭据，按同一套规则处理。
        const masked = maskText(block.text, rules, context);
        if (masked.text !== block.text) {
          onMask?.(masked);
          yield { ...chunk, block: { ...block, text: masked.text } };
          pending.delete(chunk.index);
          continue;
        }
      }
      pending.delete(chunk.index);
      yield chunk;
      continue;
    }

    // tool-call-delta 与 usage/finish 原样透传；工具参数由 tools/pre-execute 侧处理。
    yield chunk;
  }
}
