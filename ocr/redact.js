/**
 * Irreversible redaction of sensitive text inside an image.
 *
 * How it stays irreversible:
 *
 * - Sensitive spans are filled with an opaque color. There is no layer, alpha
 *   blend, or compositing that keeps the original pixels behind the fill.
 * - The whole image is re-encoded from the filled raster, so no source scanline
 *   survives in the file.
 * - Metadata is written empty, so EXIF/GPS/camera fields do not come back.
 *
 * What this cannot do: the stored attachment is content-addressed and
 * immutable, so the original file remains on disk. Redaction changes what the
 * model receives, not what the host keeps.
 */

/** Slightly over the OCR box, so antialiased edges are covered too. */
const PAD_X = 3;
const PAD_Y = 2;

/**
 * Merge overlapping or near-adjacent rectangles into a minimal cover.
 * Filling merged boxes is both cheaper and safer than filling each word box:
 * a gap between two covered words would otherwise leave a readable fragment.
 *
 * @param {{x: number, y: number, w: number, h: number}[]} boxes
 * @param {number} gap - boxes closer than this are merged.
 */
export function mergeBoxes(boxes, gap = 2) {
  const sorted = [...boxes].sort((a, b) => a.y - b.y || a.x - b.x);
  const merged = [];
  for (const box of sorted) {
    let absorbed = false;
    for (const target of merged) {
      const touchesX = box.x <= target.x + target.w + gap && target.x <= box.x + box.w + gap;
      const touchesY = box.y <= target.y + target.h + gap && target.y <= box.y + box.h + gap;
      if (!touchesX || !touchesY) continue;
      const right = Math.max(target.x + target.w, box.x + box.w);
      const bottom = Math.max(target.y + target.h, box.y + box.h);
      target.x = Math.min(target.x, box.x);
      target.y = Math.min(target.y, box.y);
      target.w = right - target.x;
      target.h = bottom - target.y;
      absorbed = true;
      break;
    }
    if (!absorbed) merged.push({ ...box });
  }
  return merged;
}

/**
 * Expand one OCR box by the padding, clamped to the image.
 * @returns {{x: number, y: number, w: number, h: number}}
 */
export function padBox(box, width, height) {
  const x = Math.max(0, Math.floor(box.x) - PAD_X);
  const y = Math.max(0, Math.floor(box.y) - PAD_Y);
  const right = Math.min(width, Math.ceil(box.x + box.w) + PAD_X);
  const bottom = Math.min(height, Math.ceil(box.y + box.h) + PAD_Y);
  return { x, y, w: Math.max(0, right - x), h: Math.max(0, bottom - y) };
}
