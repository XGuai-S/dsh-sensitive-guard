/**
 * Additional detectors for the rules that plain text patterns cannot cover.
 *
 * Three problems, three mechanisms:
 *
 * 1. **Binary and archive content** — a text rule would corrupt a base64 blob
 *    or a file reference by "masking" a chance byte sequence. These are detected
 *    first and reported as risk, then passed through untouched.
 * 2. **Address and medical-record text** — a regex can find an address-shaped
 *    run but cannot know it is an address. Detection is deliberately narrow:
 *    it fires on administrative-division chains and on clinical markers, and
 *    accepts that recall is limited.
 * 3. **Name plus identity number** — a bare name is not sensitive; a name next
 *    to an identity number is. Only the adjacent pair is masked.
 */

/** Placeholder for a combined name + identity document. */
export const PRIVACY_PAIR = '{{PRIVACY_ID}}';

/** Archival container signatures, checked on the leading bytes. */
const ARCHIVE_SIGNATURES = [
  { name: 'zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: 'zip-empty', bytes: [0x50, 0x4b, 0x05, 0x06] },
  { name: 'rar', bytes: [0x52, 0x61, 0x72, 0x21] },
  { name: '7z', bytes: [0x37, 0x7a, 0xbc, 0xaf] },
  { name: 'gzip', bytes: [0x1f, 0x8b] },
  { name: 'bz2', bytes: [0x42, 0x5a, 0x68] },
  { name: 'xz', bytes: [0xfd, 0x37, 0x7a, 0x58] },
  { name: 'tar', bytes: [0x75, 0x73, 0x74, 0x61, 0x72] },
  { name: 'pdf', bytes: [0x25, 0x50, 0x44, 0x46] },
  { name: 'sqlite', bytes: [0x53, 0x51, 0x4c, 0x69] },
];

/**
 * Identify an archive or binary container from its leading bytes.
 * @param {Uint8Array} head - first bytes of the file (16 are enough).
 * @returns {string | undefined} container name, or undefined for ordinary files.
 */
export function detectContainer(head) {
  if (!(head instanceof Uint8Array) || head.length < 2) return undefined;
  for (const signature of ARCHIVE_SIGNATURES) {
    if (head.length < signature.bytes.length) continue;
    let match = true;
    for (let index = 0; index < signature.bytes.length; index += 1) {
      if (head[index] !== signature.bytes[index]) {
        match = false;
        break;
      }
    }
    if (match) return signature.name;
  }
  return undefined;
}

/**
 * Decide whether one attachment should be treated as opaque binary.
 *
 * A NUL byte in the leading window is the practical signal: text formats never
 * contain one, and every executable or archive format does.
 *
 * @param {Uint8Array} head
 * @param {string} [name] - declared file name, used for the extension check.
 */
export function looksBinary(head, name) {
  if (typeof name === 'string' && /\.(?:zip|rar|7z|gz|bz2|xz|tar|exe|dll|so|dylib|bin|iso|dmg|msi|apk|jar|class|wasm|pdf)$/i.test(name)) {
    return true;
  }
  if (!(head instanceof Uint8Array)) return false;
  for (const byte of head) if (byte === 0x00) return true;
  return false;
}

/**
 * Chinese administrative-division chains, used as an address signal.
 *
 * A match needs at least three administrative levels ending in a street-level
 * marker, which keeps ordinary prose about a province or city out.
 */
const ADDRESS_RULES = [
  {
    id: 'cn-address',
    risk: 'high',
    to: PRIVACY_PAIR,
    // 省/自治区 + 市 + 区/县 + 街道/路/号 chain.
    re: /(?:[\u4e00-\u9fff]{2,8}(?:省|自治区|特别行政区))?[\u4e00-\u9fff]{2,8}(?:市|自治州|地区)[\u4e00-\u9fff]{2,8}(?:区|县|旗)[\u4e00-\u9fff0-9]{0,20}?(?:路|街|道|巷|号|弄|村|镇|小区|大厦|花园|公寓|单元|室)[\u4e00-\u9fff0-9]{0,20}/g,
  },
  {
    id: 'street-address',
    risk: 'high',
    to: PRIVACY_PAIR,
    // A street number plus a building, which is specific enough to act on.
    re: /[\u4e00-\u9fff]{2,12}(?:路|街|大道|巷)[0-9]{1,5}号[\u4e00-\u9fff0-9]{0,20}(?:室|层|楼|单元|栋|座|号)/g,
  },
];

/** Clinical markers that identify a medical record rather than a mention of illness. */
const MEDICAL_RULES = [
  {
    id: 'medical-record',
    risk: 'high',
    to: PRIVACY_PAIR,
    // 标签 + 取值。取值不能是证件号或护照号，那些规则已经先跑过。
    // Label plus value; the value must not be an id or passport shape, because
    // those rules run earlier and would already have replaced it.
    re: /(?:门诊号|住院号|病案号|病历号|检查报告|检验报告|处方|主诉|现病史|既往史|手术记录)\s*[:：]\s*(?![A-Z]{1,2}\d{7,8}\b)(?![\d\s]{15,19}(?!\d))[^\s，。;；]{3,}/g,
  },
  {
    id: 'diagnosis-line',
    risk: 'high',
    to: PRIVACY_PAIR,
    re: /(?:诊断|结论|病理)\s*[:：]\s*[\u4e00-\u9fffA-Za-z0-9，,、\s]{4,40}/g,
  },
  {
    id: 'medical-id',
    risk: 'high',
    to: PRIVACY_PAIR,
    // 兜底：标签后跟任意字母数字组合（含被护照规则抢先的情况）。
    // Fallback: a label followed by any alphanumeric run, including values the
    // passport rule would otherwise claim first.
    re: /(?:门诊号|住院号|病案号|病历号)\s*[:：]\s*[A-Za-z0-9]{4,}/g,
  },
];

/**
 * A name immediately followed by an identity number.
 *
 * The pair is masked as a unit because either half alone is common; only the
 * adjacency makes it identifying.
 *
 * This rule must run **before** the plain identity-number rule, or the number is
 * replaced first and the name is left behind. `buildRules` places it first for
 * that reason.
 */
export const NAME_ID_PAIR_RULE = {
  id: 'name-id-pair',
  risk: 'high',
  to: PRIVACY_PAIR,
  re: /[\u4e00-\u9fff]{2,4}(?=[^\n]{0,8}?(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d))[^\n]{0,8}?(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
};

/**
 * Rules for the privacy shapes that need more context than a single pattern.
 * The name-and-id pair is not included here: it must precede the base rules, so
 * `buildRules` places it first.
 *
 * @param {{detectAddresses?: boolean, detectMedical?: boolean}} config
 */
export function privacyRules(config = {}) {
  const rules = [];
  if (config.detectAddresses !== false) rules.push(...ADDRESS_RULES);
  if (config.detectMedical !== false) rules.push(...MEDICAL_RULES);
  return rules;
}

/**
 * Collect every QR payload from decoded BGRA pixels.
 *
 * `jsqr` is loaded lazily: it is an optional dependency, and a missing module
 * must degrade to "no QR" rather than break the guard.
 *
 * @param {Uint8Array} pixels - BGRA, width*height*4 bytes.
 * @param {number} width
 * @param {number} height
 * @returns {Promise<string[]>} decoded payloads.
 */
export async function decodeQr(pixels, width, height) {
  let jsQR;
  try {
    ({ default: jsQR } = await import('jsqr'));
  } catch {
    return [];
  }
  if (typeof jsQR !== 'function') return [];
  const rgba = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < rgba.length; index += 4) {
    // BGRA -> RGBA
    rgba[index] = pixels[index + 2];
    rgba[index + 1] = pixels[index + 1];
    rgba[index + 2] = pixels[index];
    rgba[index + 3] = 255;
  }
  try {
    const found = jsQR(rgba, width, height, { inversionAttempts: 'attemptBoth' });
    return found?.data ? [found.data] : [];
  } catch {
    return [];
  }
}
