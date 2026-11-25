/**
 * Image operations facade.
 *
 * The public surface is unchanged from the single-backend version; what changed
 * is that the backend is chosen at runtime (see `backend.js`) instead of being
 * hard-wired to Windows. Every function here delegates and never throws a
 * platform-specific error upward without context.
 */

import { selectBackend, readFileHead as readHead, DEFAULT_TIMEOUT_MS } from './backend.js';

export { DEFAULT_TIMEOUT_MS };

/** Cached selection, so probing runs once per process. */
let selection;

/**
 * Resolve the active backend once.
 * @param {{backend?: string, pythonPath?: string, tesseractPath?: string, language?: string, timeoutMs?: number}} options
 */
export async function probeOcr(options = {}) {
  selection = await selectBackend(options);
  return {
    available: selection.backend !== null && selection.ocr,
    backend: selection.name,
    platform: process.platform,
    reason: selection.reason,
  };
}

/** Return the cached selection, probing on first use. */
async function active() {
  if (selection === undefined) await probeOcr();
  if (selection?.backend === null || selection?.backend === undefined) {
    throw new Error(selection?.reason ?? 'no-backend');
  }
  return selection.backend;
}

/**
 * Recognize text and its bounding boxes in one image.
 * @param {string} imagePath
 * @param {{language?: string, timeoutMs?: number}} options
 * @returns {Promise<{text: string, x: number, y: number, w: number, h: number}[]>}
 */
export async function recognizeImageWithBoxes(imagePath, options = {}) {
  const backend = await active();
  return backend.recognize(imagePath);
}

/**
 * Recognize text only.
 * @param {string} imagePath
 * @param {{language?: string, timeoutMs?: number}} options
 * @returns {Promise<string[]>}
 */
export async function recognizeImage(imagePath, options = {}) {
  const lines = await recognizeImageWithBoxes(imagePath, options);
  return lines.map((line) => line.text);
}

/**
 * Fill rectangles with an opaque color and re-encode.
 * @param {string} imagePath
 * @param {{x: number, y: number, w: number, h: number}[]} boxes
 * @param {{outPath: string, color?: string, timeoutMs?: number}} options
 */
export async function redactImage(imagePath, boxes, options) {
  const backend = await active();
  await backend.redact(imagePath, boxes, options);
}

/**
 * Decode one image to raw BGRA pixels.
 * @param {string} imagePath
 * @param {{timeoutMs?: number}} options
 * @returns {Promise<{width: number, height: number, pixels: Uint8Array}>}
 */
export async function readImagePixels(imagePath, options = {}) {
  const backend = await active();
  return backend.pixels(imagePath);
}

/**
 * Read the leading bytes of a file, for container detection.
 * @param {string} filePath
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export async function readFileHead(filePath, length = 16) {
  return readHead(filePath, length);
}

/**
 * Downscale so the long edge fits, then re-encode as JPEG.
 * @param {string} imagePath
 * @param {{outPath: string, maxDimension?: number, timeoutMs?: number}} options
 * @returns {Promise<{width: number, height: number, data: Uint8Array}>}
 */
export async function compressImage(imagePath, options) {
  const backend = await active();
  return backend.compress(imagePath, { maxDimension: options.maxDimension ?? 2048, ...options });
}
