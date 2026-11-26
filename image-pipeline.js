/**
 * 图片分析 / Image analysis.
 *
 * 一条消息里的图片按顺序经过四道处理：二进制标记、二维码解码、OCR 文本扫描、
 * 涂改或压缩。每一步都可能失败，而失败从不是中断对话的理由——只记录并放行。
 *
 * An image passes four stages in order: binary marking, QR decoding, OCR text
 * scanning, then redaction or compression. Every stage can fail, and a failure
 * is never a reason to abort the turn — it is recorded and the image passes.
 *
 * 这个模块从 `index.js` 抽出来，是因为它占用了那个文件近三分之一的行数，
 * 且与「分级扫描」这一核心职责无关。
 *
 * This module left `index.js` because it occupied nearly a third of that file
 * and has nothing to do with the core responsibility of leveled scanning.
 */

import { readFile, rm } from 'node:fs/promises';
import {
  recognizeImageWithBoxes, redactImage, readImagePixels, readFileHead, compressImage,
} from './ocr/runner.js';
import { readImageText } from './ocr/normalize.js';
import { mergeBoxes, padBox } from './ocr/redact.js';
import { detectContainer, looksBinary, decodeQr } from './ocr/detect.js';
import { scanText } from './masking.js';
import { LEVELS } from './rules.js';

/**
 * 分析一批消息里的图片 / Analyze the images of one message batch.
 *
 * @param {object[]} messages 待分析消息 / messages to inspect
 * @param {{
 *   config: object,
 *   logger: {info: Function, warn: Function, error: Function},
 *   attachments?: {imageHostPath?: Function, saveImage?: Function},
 *   scanned: Set<string>,
 *   context: object,
 *   ocrRules: object[],
 * }} deps 依赖集合 / injected dependencies
 * @returns {Promise<{
 *   found: object[],
 *   unreliable: string[],
 *   replacements: Map<string, object>,
 *   scanned: number,
 * }>}
 */
export async function analyzeImages(messages, deps) {
  const { config, logger, attachments, scanned: seen, context, ocrRules } = deps;
  const found = [];
  const unreliable = [];
  const replacements = new Map();
  let scanned = 0;

  for (const message of messages) {
    if (typeof message?.content === 'string') continue;
    for (const block of message?.content ?? []) {
      if (block?.type !== 'image') continue;
      const attachmentId = block.attachment?.attachmentId;
      if (typeof attachmentId !== 'string' || seen.has(attachmentId)) continue;

      if (scanned >= config.ocrMaxImagesPerTurn) {
        logger.warn(`放行-OCR超限 本轮仅分析前 ${config.ocrMaxImagesPerTurn} 张`);
        return { found, unreliable, replacements, scanned };
      }
      seen.add(attachmentId);
      scanned += 1;

      const outcome = await analyzeOne(block, attachmentId, {
        config, logger, attachments, context, ocrRules,
      });
      if (outcome.unreliable === true) unreliable.push(attachmentId);
      if (outcome.replacement !== undefined) replacements.set(attachmentId, outcome.replacement);
      if (outcome.lines !== undefined) found.push(...outcome.lines);
    }
  }
  return { found, unreliable, replacements, scanned };
}

/**
 * 分析一张图片 / Analyze one image.
 *
 * @param {object} block 图片块 / image block
 * @param {string} attachmentId
 * @param {object} deps
 * @returns {Promise<{unreliable?: boolean, replacement?: object, lines?: object[]}>}
 */
async function analyzeOne(block, attachmentId, deps) {
  const { config, logger, attachments, context, ocrRules } = deps;

  let hostPath;
  try {
    hostPath = attachments?.imageHostPath?.(block.attachment);
  } catch {
    hostPath = undefined;
  }
  if (typeof hostPath !== 'string') {
    logger.warn('OCR识别不可靠 附件无宿主路径，已抹除元数据后放行');
    return { unreliable: true };
  }

  // 二进制与压缩包不解析内部，只标记放行。
  if (config.markBinary) {
    try {
      const head = await readFileHead(hostPath, 16);
      const container = detectContainer(head);
      if (container !== undefined || looksBinary(head, block.attachment.name)) {
        logger.warn(`放行-二进制内容 ${container ?? 'binary'}，未解析内部`);
        return {};
      }
    } catch {
      // 读取失败不构成跳过 OCR 的理由 / a failed head read is not a reason to skip OCR.
    }
  }

  // 二维码：码内内容独立于画面文字。
  if (config.detectQr) {
    await scanQr(hostPath, { config, logger, context, ocrRules });
  }

  const read = await readImageText(
    (path) => recognizeImageWithBoxes(path, { language: config.ocrLanguage, timeoutMs: config.ocrTimeoutMs }),
    hostPath,
  );
  if (!read.ok) {
    logger.warn(`OCR识别不可靠 ${read.reason ?? 'unknown'}，已抹除元数据后放行`);
    return { unreliable: true };
  }
  if (read.unreliable.length > 0) {
    logger.warn(`OCR识别不可靠 ${read.unreliable.length} 行未达可信阈值，已忽略`);
  }

  // 命中行整行涂改：引擎不返回字符级偏移，只涂子串会留下可读碎片。
  // Whole-line coverage: the engine reports no per-character offsets, so a
  // partial fill would leave a readable fragment beside it.
  const hitLines = [];
  const cleanLines = [];
  for (const line of read.lines) {
    if (matchesAnyRule(line.text, ocrRules)) hitLines.push(line);
    else cleanLines.push(line);
  }

  if (hitLines.length === 0) {
    const replacement = await maybeCompress(block, attachmentId, hostPath, { config, logger, attachments });
    return { lines: cleanLines, replacement };
  }

  const replacement = await maybeRedact(block, hostPath, hitLines, { config, logger, attachments });
  return { lines: [...cleanLines, ...hitLines], replacement };
}

/**
 * 一行文本是否命中任一规则 / Whether one line matches any rule.
 * @param {string} text
 * @param {object[]} rules
 */
function matchesAnyRule(text, rules) {
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    const hit = rule.re.test(text);
    rule.re.lastIndex = 0;
    if (hit) return true;
  }
  return false;
}

/**
 * 解码并扫描二维码 / Decode and scan QR payloads.
 *
 * 码内内容无法就地改写：涂掉整个码会毁掉它，而码本身不是「行」结构。
 * 因此只记录风险。
 *
 * A QR payload cannot be edited in place: covering the code destroys it, and a
 * code is not a line. The risk is therefore recorded only.
 */
async function scanQr(hostPath, deps) {
  const { config, logger, context, ocrRules } = deps;
  try {
    const decoded = await readImagePixels(hostPath, { timeoutMs: config.ocrTimeoutMs });
    for (const payload of await decodeQr(decoded.pixels, decoded.width, decoded.height)) {
      const result = scanText(payload, ocrRules, context);
      if (result.level !== LEVELS.pass) {
        logger.warn(`二维码命中 level=${result.level}，画内码无法就地改写，已标记风险`);
      }
    }
  } catch (error) {
    logger.warn(`二维码解析异常 ${error?.message ?? 'unknown'}，继续流转`);
  }
}

/**
 * 无敏感内容时按需压缩 / Compress when nothing sensitive was found.
 * @returns {Promise<object|undefined>} 新附件引用 / new attachment reference
 */
async function maybeCompress(block, attachmentId, hostPath, deps) {
  const { config, logger, attachments } = deps;
  const longEdge = Math.max(block.attachment.width, block.attachment.height);
  if (!config.compressImages || longEdge <= config.compressMaxDimension) return undefined;

  const outPath = `${hostPath}.small.bin`;
  try {
    const shrunk = await compressImage(hostPath, {
      outPath,
      maxDimension: config.compressMaxDimension,
      timeoutMs: config.ocrTimeoutMs,
    });
    const saved = await attachments.saveImage({
      data: shrunk.data,
      mediaType: 'image/jpeg',
      name: block.attachment.name ?? 'compressed.jpg',
    });
    logger.info(`✅已压缩 ${block.attachment.width}×${block.attachment.height} → ${shrunk.width}×${shrunk.height}`);
    return saved;
  } catch (error) {
    logger.warn(`压缩失败 ${error?.message ?? 'unknown'}，图片保持原样`);
    return undefined;
  } finally {
    await rm(outPath, { force: true }).catch(() => {});
  }
}

/**
 * 涂改命中行 / Cover the hit lines.
 * @returns {Promise<object|undefined>} 新附件引用 / new attachment reference
 */
async function maybeRedact(block, hostPath, hitLines, deps) {
  const { config, logger, attachments } = deps;
  if (!config.redactImages) return undefined;

  const boxes = mergeBoxes(hitLines.map((line) => padBox(line, block.attachment.width, block.attachment.height)));
  const outPath = `${hostPath}.redacted.png`;
  try {
    await redactImage(hostPath, boxes, { outPath, color: config.redactColor, timeoutMs: config.ocrTimeoutMs });
    const data = await readFile(outPath).catch(() => undefined);
    if (data === undefined) throw new Error('redacted-file-missing');
    const saved = await attachments.saveImage({
      data,
      mediaType: 'image/png',
      name: block.attachment.name ?? 'redacted.png',
    });
    logger.warn(`已涂改图片 覆盖 ${boxes.length} 个区域`);
    return saved;
  } catch (error) {
    logger.warn(`涂改失败 ${error?.message ?? 'unknown'}，图片保持原样`);
    return undefined;
  } finally {
    await rm(outPath, { force: true }).catch(() => {});
  }
}

/**
 * 把图片替换写回消息 / Repoint image blocks at their replacements.
 *
 * @param {object[]} messages
 * @param {Map<string, object>} replacements
 * @returns {{messages: object[], changed: boolean}}
 */
export function applyReplacements(messages, replacements) {
  if (replacements.size === 0) return { messages, changed: false };
  let changed = false;
  const next = messages.map((message) => {
    if (typeof message?.content === 'string' || !Array.isArray(message?.content)) return message;
    let touched = false;
    const content = message.content.map((block) => {
      if (block?.type !== 'image') return block;
      const replacement = replacements.get(block.attachment?.attachmentId);
      if (replacement === undefined) return block;
      touched = true;
      // 合并而非替换：saveImage 返回的新引用通常只有 attachmentId/mediaType/name，
      // 若直接顶替会丢掉 width/height/bytes，DSH 无法渲染图片，表现为「附件发不了」。
      // Merge instead of replace: keep the original width/height/bytes so DSH can
      // still render the image after redaction/compression.
      return { ...block, attachment: { ...block.attachment, ...replacement } };
    });
    if (!touched) return message;
    changed = true;
    return { ...message, content };
  });
  return { messages: next, changed };
}
