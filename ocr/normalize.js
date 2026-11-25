/**
 * OCR normalization and redaction planning.
 *
 * Windows.Media.Ocr emits CJK text with a space between characters and
 * sometimes splits an ASCII run in two (`sk-abcdefghijklmnopl 234`). Matching a
 * pattern against that raw text silently misses every secret, so the text is
 * normalized before it is scanned and the OCR-specific patterns below also run
 * against a space-tolerant variant.
 */

/**
 * Collapse the inter-character spacing the CJK recognizer inserts.
 *
 * Only CJK spacing is removed. ASCII runs are deliberately left alone: the
 * recognizer also splits ASCII tokens (`sk-abcdefghijklmnopl 234`), and joining
 * every ASCII gap would turn `hello world` into `helloworld`. The split-token
 * case is handled by the `ocr-split-secret` rule instead, which matches across
 * the space.
 */
export function normalizeOcrText(text) {
  if (typeof text !== 'string') return '';
  return text
    // Spaces between two CJK characters carry no meaning.
    .replace(/(?<=[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef])\s+(?=[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef])/g, '')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * Decide whether a recognized line is trustworthy enough to act on.
 *
 * The Chinese recognizer reports 0.000 confidence for every word, so a
 * confidence threshold cannot work here. Instead the text is judged on shape:
 * a line that is mostly symbols or has no recognizable alphanumeric/CJK content
 * is treated as unreliable and reported as such.
 *
 * @param {string} rawLine - one recognized line, before normalization.
 * @param {{minAlnumRatio?: number, minChars?: number}} options
 */
export function assessOcrLine(rawLine, options = {}) {
  const minChars = options.minChars ?? 2;
  const minRatio = options.minAlnumRatio ?? 0.3;
  const normalized = normalizeOcrText(rawLine);
  const meaningful = normalized.replace(/\s/g, '');
  if (meaningful.length < minChars) return { reliable: false, reason: 'too-short', text: normalized };
  const alnum = (meaningful.match(/[A-Za-z0-9\u4e00-\u9fff]/g) ?? []).length;
  const ratio = alnum / meaningful.length;
  if (ratio < minRatio) return { reliable: false, reason: 'low-signal', text: normalized };
  return { reliable: true, reason: undefined, text: normalized };
}

/** OCR-specific patterns, applied to the normalized text of a recognized line. */
export const OCR_RULES = [
  {
    id: 'ocr-split-secret',
    risk: 'high',
    to: '{{SECRET_TOKEN}}',
    // A prefix whose token body was broken across a space boundary.
    re: /(?<![\w-])(?:sk-|ghp_|gho_|github_pat_|glpat-|npm_|hf_|xox[baprs]-)[A-Za-z0-9_-]*(?:\s[A-Za-z0-9_-]+)?/g,
  },
  {
    id: 'ocr-cn-mobile',
    risk: 'high',
    to: '{{PRIVACY_ID}}',
    // Phone numbers printed with separators: 138 0013 8000 / 138-0013-8000.
    re: /(?<!\d)1[3-9]\d(?:[ -]?\d{4}){2}(?!\d)/g,
  },
  {
    id: 'ocr-cn-id',
    risk: 'high',
    to: '{{PRIVACY_ID}}',
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
  },
  {
    id: 'ocr-label-value',
    risk: 'high',
    to: '{{CRED_CODE}}',
    // Requires a real separator. A bare label word followed by a space would
    // otherwise swallow the next token, and that token is often a secret the
    // rules above already replaced with a placeholder.
    re: /((?:密码|口令|验证码|密钥|账号|password|passwd|pwd|pin|otp)\s*[:：=]\s*)[^\s]{4,}/gi,
    keepGroup: 1,
  },
  {
    id: 'ocr-signed-url',
    risk: 'high',
    to: '{{CRED_CODE}}',
    // A QR usually carries a URL, and the sensitive part is the query string.
    // `token=abc123` must not survive just because it arrived inside a link.
    re: /((?:[?&](?:token|ticket|code|sign|sig|key|auth|session|password)=))[^&\s#]{3,}/gi,
    keepGroup: 1,
  },
  {
    id: 'ocr-url',
    risk: 'normal',
    to: '{{PRIVATE_URL}}',
    re: /\bhttps?:\/\/[^\s"'<>]+/gi,
  },
];

/**
 * Extract the OCR-visible text of an image.
 *
 * @param {(imagePath: string) => Promise<{text: string, x: number, y: number, w: number, h: number}[]>} runOcr
 *   platform runner; resolves to recognized lines with pixel rectangles.
 * @param {string} imagePath
 * @returns {Promise<{ok: boolean, lines: object[], unreliable: string[], reason?: string}>}
 */
export async function readImageText(runOcr, imagePath) {
  let raw;
  try {
    raw = await runOcr(imagePath);
  } catch (error) {
    return { ok: false, lines: [], unreliable: [], reason: error?.message ?? 'ocr-failed' };
  }
  if (!Array.isArray(raw)) return { ok: false, lines: [], unreliable: [], reason: 'ocr-no-output' };
  const lines = [];
  const unreliable = [];
  for (const entry of raw) {
    const verdict = assessOcrLine(entry.text);
    if (verdict.reliable) {
      lines.push({ ...entry, text: verdict.text });
    } else {
      unreliable.push(verdict.text);
    }
  }
  return { ok: true, lines, unreliable };
}
