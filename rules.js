/**
 * 规则集与识别逻辑 / Rule tables and detection.
 *
 * 本文件只负责「识别什么」和「替换成什么」，不关心挂载点。
 * This module owns what is matched and what it becomes; it never touches a
 * hook point.
 *
 * 设计要点 / Design notes:
 *
 * - 每条规则用 `keepGroup` 保留键名与分隔符，只替换取值，因此 JSON、YAML、
 *   properties、gradle 的结构不会被破坏。
 * - 占位符一旦写入，后续规则不再匹配，保证同一个值只替换一次。
 * - 高熵兜底必须排除端口、版本号与十六进制哈希，否则会把普通标识符也当密钥。
 */

/** 占位符词表 / Placeholder vocabulary. */
export const PLACEHOLDERS = Object.freeze({
  secret: '{{SECRET_TOKEN}}',
  privacy: '{{PRIVACY_ID}}',
  cred: '{{CRED_CODE}}',
  otp: '{{ONE_TIME_CODE}}',
  path: '{{LOCAL_PATH}}',
  device: '{{DEVICE_ID}}',
  email: '{{EMAIL_ADDR}}',
  net: '{{NET_IP}}',
  url: '{{PRIVATE_URL}}',
  db: '{{DB_CRED}}',
});

/** 文档示例值，永不脱敏 / Documentation samples that are never masked. */
export const DEFAULT_WHITELIST = [
  'test-key',
  'demo-sk',
  'example-token',
  'placeholder',
  'mock-secret',
  'md5',
  'sha256',
];

/**
 * 命中分类，用于日志标注 / Hit categories, used in log labels.
 * 规格要求日志标注命中类型：账号 / 密码 / api密钥 / 验证码 / 可疑长串。
 */
export const HIT_KINDS = Object.freeze({
  secret: 'api密钥',
  account: '账号',
  password: '密码',
  otp: '验证码',
  entropy: '可疑长串',
  privacy: '身份隐私',
  path: '本地路径',
  device: '设备信息',
  net: '网络地址',
});

const MAX_SCAN_CHARS = 4 * 1024 * 1024;

/**
 * 键值对前缀：键名 + 可选闭合引号 + 分隔符 + 可选起始引号。
 * KV prefix: key name, optional closing quote, separator, optional opening quote.
 *
 * 必须允许键名后紧跟引号，否则 JSON 的 `{"password":"x"}` 匹配不到。
 * 复合键名允许 `.`、`_`、`-` 三种连接符，覆盖 properties 与 gradle 写法。
 *
 * The closing quote after the key is required for JSON (`{"password":"x"}`).
 * Compound keys accept `.`, `_`, and `-` so properties and gradle styles work.
 */
const KV_KEY = String.raw`(?:password|passwd|pwd|secret|token|apikey|api[._-]?key|access[._-]?key|access[._-]?token|auth[._-]?token|client[._-]?secret|private[._-]?key|storePassword|keyPassword|pkcs12(?:Password)?|signaturePassword|bearer|credential|账号|帐号|用户名|密码|口令|数据库密码|wifi密码|密钥)`;

const KV_PREFIX = String.raw`((?:${KV_KEY})\s*["'` + '`' + String.raw`]?\s*[:=：]\s*["'` + '`' + String.raw`]?)`;

/** 固定前缀密钥 / Fixed-prefix keys. */
const KEY_PREFIX = String.raw`(?:sk-proj-|sk-ant-|sk-|ghp_|gho_|github_pat_|glpat-|AKIA|ASIA|LTAI|AKID|AIza|hf_|xox[baprs]-|sk_live_|rk_test_|whsec_|npm_)`;

/**
 * 基础规则表 / Base rule table.
 *
 * `kind` 只用于日志标注，`risk` 决定日志等级，两者都不改变「一律脱敏」的行为。
 * `kind` labels the log line, `risk` sets its level; neither changes the
 * "always mask" behaviour.
 */
const BASE_RULES = [
  // --- 明文密钥 / secrets ---
  {
    id: 'private-key',
    risk: 'high',
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----/g,
  },
  {
    id: 'key-prefix',
    risk: 'high',
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: new RegExp(String.raw`(?<![\w-])${KEY_PREFIX}[A-Za-z0-9_-]{8,}`, 'g'),
  },
  {
    id: 'jwt',
    risk: 'high',
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: /(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: 'bearer',
    risk: 'high',
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: /((?:Authorization\s*:\s*)?Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/gi,
    keepGroup: 1,
  },
  {
    id: 'kv-credential',
    risk: 'high',
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    // 取值排除分隔符与空白；JSON 的 `"` 与 `}` 也要排除，才能只吃掉值。
    // The value stops at a separator or whitespace; quotes and braces are
    // excluded so a JSON value is replaced without breaking its structure.
    re: new RegExp(String.raw`${KV_PREFIX}([^\s"'` + '`' + String.raw`,;)}\]]{3,})`, 'gi'),
    keepGroup: 1,
  },

  // --- 身份隐私 / identity ---
  {
    id: 'cn-id-card',
    risk: 'high',
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
  },
  {
    id: 'cn-mobile',
    risk: 'high',
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
  },
  {
    id: 'bank-card',
    risk: 'high',
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)\d{16,19}(?!\d)/g,
    validate: luhn,
  },
  {
    id: 'passport',
    risk: 'high',
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<![\w])(?:E\d{8}|[GH]\d{8})(?![\w])/g,
  },

  // --- 验证码 / one-time codes ---
  {
    id: 'one-time-code',
    risk: 'high',
    kind: HIT_KINDS.otp,
    to: PLACEHOLDERS.otp,
    // 关键词 + 4–6 位数字，关键词与数字之间允许少量分隔符。
    re: /((?:验证码|短信码|校验码|动态码|verify|verification|otp|totp|one[- ]?time(?: code| password)?|2fa|code)\s*[:：=是为]?\s*)(\d{4,6})(?!\d)/gi,
    keepGroup: 1,
  },

  // --- 系统凭证 / system credentials ---
  {
    id: 'service-password',
    risk: 'high',
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    re: /((?:adb|root|ssh|server|database|db|mysql|postgres|redis|wifi|wi-fi|router)[^\n]{0,24}?(?:password|passwd|pwd|密码|口令)\s*[:=：]\s*)["'`]?[^\s"'`,;]{3,}/gi,
    keepGroup: 1,
  },
  {
    id: 'cookie-session',
    risk: 'high',
    kind: HIT_KINDS.cred,
    to: PLACEHOLDERS.cred,
    re: /((?:cookie|set-cookie|session[_-]?id|jsessionid|phpsessid)\s*[:=]\s*)[^\s;,\n]{8,}/gi,
    keepGroup: 1,
  },
  {
    id: 'temp-login-link',
    risk: 'high',
    kind: HIT_KINDS.cred,
    to: PLACEHOLDERS.cred,
    re: /\bhttps?:\/\/[^\s"'<>]{6,}?\?(?:[^\s"'<>]*?(?:token|ticket|code|sign|sig|expires|key)=)[^\s"'<>]{6,}/gi,
  },

  // --- 本地路径 / local paths ---
  {
    id: 'local-path',
    risk: 'normal',
    kind: HIT_KINDS.path,
    to: PLACEHOLDERS.path,
    re: /(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\s"'<>|,;)\]}]+|\/storage\/emulated\/\d+\/[^\s"'<>|,;)\]}]*|\/root\/[^\s"'<>|,;)\]}]*|\/home\/[^\s"'<>|,;)\]}]+|\/Users\/[^\s"'<>|,;)\]}]+)/g,
  },

  // --- 设备信息 / device ids ---
  {
    id: 'device-id',
    risk: 'normal',
    kind: HIT_KINDS.device,
    to: PLACEHOLDERS.device,
    re: /\b(?:[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{16})\b/g,
    validate: (value) => !/^\d+$/.test(value.replace(/-/g, '')),
  },

  // --- 网络地址 / network ---
  {
    id: 'net-ip',
    risk: 'normal',
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.net,
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    validate: isMaskableIp,
  },
];

/** 内网专用后缀 / Internal-only host suffixes. */
const INTERNAL_SUFFIXES = ['internal', 'local', 'lan', 'corp', 'intra', 'private', 'svc', 'home'];

/** 公网后缀，仅在 `maskUrls: 'all'` 时使用 / Public suffixes, only for 'all'. */
const PUBLIC_SUFFIXES = ['com', 'net', 'org', 'cn', 'io', 'dev', 'ai', 'co', 'top', 'xyz', 'me', 'app', 'site', 'cloud', 'tech'];

/** 校验：银行卡 Luhn / Luhn check for card numbers. */
export function luhn(value) {
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = value.charCodeAt(index) - 48;
    if (digit < 0 || digit > 9) return false;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** 回环与广播地址不视为部署机密 / Loopback and broadcast are not secrets. */
function isMaskableIp(value) {
  return value !== '127.0.0.1' && value !== '0.0.0.0' && value !== '255.255.255.255';
}

/**
 * 排除项：端口、版本号、十六进制哈希。
 * Exclusions: ports, version numbers, hex hashes.
 *
 * 规格明确要求这些不判定为凭证。哈希串熵值很高，若不排除会被高熵兜底全部吃掉。
 */
export function isExcluded(value) {
  if (!/^[A-Za-z0-9._+/-]+$/.test(value)) return false;
  // 纯数字且落在端口范围内。
  if (/^\d{1,5}$/.test(value)) {
    const port = Number(value);
    if (port >= 1 && port <= 65535) return true;
  }
  // 版本号：1.2.3 / v1.2.3 / 1.2.3-beta.1
  if (/^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/i.test(value)) return true;
  // md5 / sha1 / sha256 / sha512
  if (/^[0-9a-f]{32}$/i.test(value)) return true;
  if (/^[0-9a-f]{40}$/i.test(value)) return true;
  if (/^[0-9a-f]{64}$/i.test(value)) return true;
  if (/^[0-9a-f]{128}$/i.test(value)) return true;
  return false;
}

/**
 * 高熵判定：字符种类足够多且长度达标，才视为可疑凭证。
 * High-entropy test: enough character classes and enough length.
 *
 * 长度阈值取 24（规格要求 ≥24）。同时要求至少三类字符，避免把长英文单词、
 * 长标识符误判成密钥。
 */
export function isHighEntropy(value) {
  if (typeof value !== 'string' || value.length < 24) return false;
  if (isExcluded(value)) return false;
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/\d/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  // 至少三类字符：纯小写长串是英文单词或标识符，不是密钥。
  if (classes < 3) return false;
  // 去重后字符数太少，说明是重复填充而非随机串。
  const distinct = new Set(value).size;
  if (distinct < 12) return false;
  // 香农熵下限：排除 aaaaaBBB123456... 这类低熵填充。
  return shannonEntropy(value) >= 3.0;
}

/**
 * 香农熵（每字符比特数）/ Shannon entropy in bits per character.
 * 随机生成的密钥通常 > 3.5；结构化标识符通常 < 3.0。
 * Random keys usually exceed 3.5; structured identifiers stay below 3.0.
 */
export function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** 构建 URL 规则 / Build the URL rules for one configuration. */
function urlRules(config) {
  const level = config.maskUrls;
  if (level === false) return [];
  const rules = [];
  const internal = config.privateUrlSuffixes ?? INTERNAL_SUFFIXES;
  rules.push({
    id: 'private-url',
    risk: 'normal',
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.url,
    re: new RegExp(`\\b(?:https?:\\/\\/)?(?:[a-z0-9-]+\\.)+(?:${internal.join('|')})\\b[A-Za-z0-9/._~:%?#@!$&'*+,;=-]*`, 'gi'),
  });
  if (level === true || level === 'all') {
    rules.push({
      id: 'domain',
      risk: 'normal',
      kind: HIT_KINDS.net,
      to: PLACEHOLDERS.url,
      re: new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${PUBLIC_SUFFIXES.join('|')})\\b`, 'gi'),
    });
  }
  return rules;
}

/** 可选规则 / Optional rules. */
function optionalRules(config) {
  const rules = [];
  if (config.maskDbCredentials) {
    rules.push({
      id: 'db-credential',
      risk: 'high',
      kind: HIT_KINDS.cred,
      to: PLACEHOLDERS.db,
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'<>]*/gi,
    });
  }
  rules.push({
    id: 'email',
    risk: 'normal',
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.email,
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  });
  rules.push(...urlRules(config));
  return rules;
}

/**
 * 组装规则表 / Assemble the rule table.
 *
 * 顺序很重要 / Order matters:
 *
 * - 「姓名+证件」必须排在身份证规则之前，否则证件先被替换，姓名留在原地。
 * - 具体规则在前，高熵兜底在最后，否则兜底会先吃掉本应精确分类的值。
 * - 住址与病历规则由调用方通过 `extraRules` 注入，避免 rules.js 反向依赖
 *   ocr/detect.js 造成循环引用。
 *
 * The name-and-id pair must precede the identity-number rule, or the number is
 * replaced first and the name is left behind. Specific rules come before the
 * entropy fallback. Address and medical rules arrive through `extraRules`, so
 * this module never imports the OCR layer.
 *
 * @param {object} config 归一化配置 / normalized config
 * @param {object[]} [extraRules] 额外规则（住址、病历、姓名+证件）/ extra rules
 */
export function buildRules(config, extraRules = []) {
  const rules = [...extraRules, ...BASE_RULES, ...optionalRules(config)];
  if (config.detectHighEntropy !== false) {
    rules.push({
      id: 'high-entropy',
      risk: 'high',
      kind: HIT_KINDS.entropy,
      to: PLACEHOLDERS.secret,
      // 边界不含 `=`：`password=value` 里的 `=` 是分隔符，高熵只该吃掉取值，
      // 否则整段连键名一起被替换，KV 规则的精确分类就丢了。
      // `=` is excluded from the boundary: in `password=value` it is a
      // separator, so the fallback must take the value alone.
      re: /(?<![\w+/=-])[A-Za-z0-9+/_-]{24,}(?![\w+/=-])/g,
      validate: isHighEntropy,
    });
  }
  return rules.filter((rule) => !config.disabledRules?.includes(rule.id));
}
