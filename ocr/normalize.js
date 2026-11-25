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

/**
 * OCR 专用规则 / OCR-specific patterns.
 *
 * 识别引擎会插入空格、拆断 ASCII 串，因此这些规则比主规则表更宽容。
 * 只用于「判断某一行是否命中」和「对码内文本做替换」，不替代主规则表。
 *
 * The recognizer inserts spaces and splits ASCII runs, so these are more
 * permissive than the main table. They decide whether a line is sensitive and
 * mask QR payloads; they do not replace the main table.
 */
export const OCR_RULES = [
  {
    id: 'ocr-split-secret',
    risk: 'high',
    kind: 'api密钥',
    to: '{{SECRET_TOKEN}}',
    // 前缀后可能被空格拆断 / the body may be split by a space.
    re: /(?<![\w-])(?:sk-proj-|sk-ant-|sk-|ghp_|gho_|github_pat_|glpat-|npm_|hf_|xox[baprs]-)[A-Za-z0-9_-]*(?:\s[A-Za-z0-9_-]+)?/g,
  },
  {
    id: 'ocr-cn-mobile',
    risk: 'high',
    kind: '身份隐私',
    to: '{{PRIVACY_ID}}',
    // 带分隔符的手机号 / phone numbers printed with separators.
    re: /(?<!\d)1[3-9]\d(?:[ -]?\d{4}){2}(?!\d)/g,
  },
  {
    id: 'ocr-cn-id',
    risk: 'high',
    kind: '身份隐私',
    to: '{{PRIVACY_ID}}',
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
  },
  {
    id: 'ocr-one-time-code',
    risk: 'high',
    kind: '验证码',
    to: '{{ONE_TIME_CODE}}',
    // 验证码：关键词 + 4–6 位数字 / keyword then 4–6 digits.
    re: /((?:验证码|短信码|校验码|动态码|verify|verification|otp|totp|2fa|code)\s*[:：=是为]?\s*)(\d{4,6})(?!\d)/gi,
    keepGroup: 1,
  },
  {
    id: 'ocr-label-value',
    risk: 'high',
    kind: '密码',
    to: '{{CRED_CODE}}',
    // 必须有真实分隔符；只写标签词会吞掉下一个词。
    // Requires a real separator; a bare label would swallow the next token.
    re: /((?:密码|口令|密钥|账号|password|passwd|pwd|pin)\s*[:：=]\s*)[^\s]{4,}/gi,
    keepGroup: 1,
  },
  {
    id: 'ocr-signed-url',
    risk: 'high',
    kind: '系统凭证',
    to: '{{CRED_CODE}}',
    // 二维码通常承载 URL，敏感部分在查询串里。
    // A QR usually carries a URL, and the sensitive part is the query string.
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
