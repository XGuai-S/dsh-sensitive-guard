/**
 * 规则集与分级定义 / Rule tables and level definitions.
 *
 * 本文件只负责「识别什么」「替换成什么」「属于哪一级」，不关心挂载点。
 * This module owns what is matched, what it becomes, and which level it
 * belongs to; it never touches a hook point.
 *
 * 三级分类 / Three levels:
 *
 * - **BLOCK** 阻断：泄露后果不可逆（私钥、身份、支付、高权限密码、联系方式、
 *   验证码、详细住址）。命中即拦截，不写 session、不转发模型。
 * - **MASK** 脱敏：隐私风险但非直接资金/权限损失（网络、设备、会话、交易、
 *   证书、路径、指纹）。替换为占位符后正常写入。
 * - **PASS** 放行：白名单与无敏感内容，原文写入。
 *
 * 识别优先级 / Recognition priority:
 *   白名单 > 绕过判定 > BLOCK > MASK > PASS
 */

/** 占位符词表 / Placeholder vocabulary. */
export const PLACEHOLDERS = Object.freeze({
  secret: '{{SECRET_TOKEN}}',
  privacy: '{{PRIVACY_ID}}',
  cred: '{{CRED_CODE}}',
  social: '{{SOCIAL_ID}}',
  otp: '{{ONE_TIME_CODE}}',
  net: '{{NET_IP}}',
  lan: '{{LAN_IP}}',
  mac: '{{MAC_ADDR}}',
  email: '{{EMAIL_ADDR}}',
  path: '{{LOCAL_PATH}}',
  device: '{{DEVICE_ID}}',
  home: '{{HOME_ADDR}}',
  trade: '{{TRADE_NO}}',
  cert: '{{CERT_INFO}}',
  fingerprint: '{{KEY_FINGERPRINT}}',
  db: '{{DB_CRED}}',
  url: '{{PRIVATE_URL}}',
});

/** 分级 / Levels. */
export const LEVELS = Object.freeze({ block: 'BLOCK', mask: 'MASK', pass: 'PASS', error: 'ERROR' });

/**
 * 白名单降噪 / Whitelist noise reduction.
 *
 * 规格要求白名单优先级最高，命中即跳过所有阻断与脱敏规则。
 * The spec puts the whitelist above every other rule.
 */
export const DEFAULT_WHITELIST = [
  // 回环与广播
  '127.0.0.1', '::1', '0.0.0.0', '255.255.255.255',
  // 示例域名
  'example.com', 'example.org', 'example.net', 'localhost',
  // 示例值与占位
  'test-key', 'demo-key', 'demo-sk', 'test-token', 'example-token',
  'mock-secret', 'placeholder', 'your_key', 'your-key', 'yourkey',
  'xxx', 'xxxx', 'changeme', 'test/password',
  // 哈希算法名
  'md5', 'sha1', 'sha256', 'sha512',
  // 样板测试数据
  '6222000000000000', '4111111111111111', '5555555555554444',
  '110101199003074512', '13800138000', '13800138001',
];

/**
 * 命中分类 / Hit kinds, used in structured logs.
 */
export const HIT_KINDS = Object.freeze({
  secret: 'api密钥',
  password: '密码',
  account: '账号',
  otp: '验证码',
  entropy: '可疑长串',
  privacy: '身份隐私',
  contact: '联系方式',
  social: '社交账号',
  address: '住址',
  path: '本地路径',
  device: '设备信息',
  net: '网络地址',
  mac: 'MAC地址',
  email: '邮箱',
  fingerprint: '密钥指纹',
  trade: '交易号',
  cert: '证书信息',
  bypass: '绕过尝试',
});

/** 高风险类型，单独告警等级 / High-risk kinds. */
export const HIGH_RISK_KINDS = new Set([
  HIT_KINDS.secret, HIT_KINDS.privacy, HIT_KINDS.password,
  HIT_KINDS.otp, HIT_KINDS.contact, HIT_KINDS.address,
  HIT_KINDS.fingerprint, HIT_KINDS.cert,
]);

/** 扫描上限 / Scan bounds. */
export const MAX_SCAN_CHARS = 4 * 1024 * 1024;
/** 分片大小 / Chunk size for large text. */
export const CHUNK_SIZE = 4096;
/** 递归深度上限 / Recursion depth bound. */
export const MAX_RECURSE_DEPTH = 3;

/**
 * 键值对前缀 / KV prefix.
 *
 * 允许键名后跟闭合引号（JSON），也允许 `.`、`_`、`-` 连接。
 * 分隔符覆盖 `=`、`:`、`=>`、`：`，以及可选起始引号。
 */
const KV_KEY = [
  'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'apikey', 'api[._-]?key',
  'accesskey', 'access[._-]?key', 'access[._-]?token', 'auth', 'authorization',
  'bearer', 'sshkey', 'ssh[._-]?key', 'private[._-]?key', 'passphrase',
  'client[._-]?secret', 'storePassword', 'keyPassword', 'pkcs12(?:Password)?',
  'signaturePassword', 'credential',
  '账号', '帐号', '用户名', '密码', '口令', '数据库密码', 'wifi密码', '支付密钥', '密钥',
].join('|');

const KV_PREFIX = String.raw`((?:${KV_KEY})\s*["'` + '`' + String.raw`]?\s*(?:=>|[:=：])\s*["'` + '`' + String.raw`]?)`;

/** 取值终止符 / Value terminators. */
const KV_VALUE = String.raw`([^\s"'` + '`' + String.raw`,;)}\]]{3,})`;

/** 固定前缀密钥 / Fixed-prefix keys. */
const KEY_PREFIX = [
  'sk-proj-', 'sk-ant-', 'sk-', 'ghp_', 'gho_', 'github_pat_', 'glpat-',
  'AKIA', 'ASIA', 'LTAI', 'AKID', 'AIza', 'hf_', 'xox[baprs]-',
  'sk_live_', 'rk_test_', 'whsec_', 'npm_', 'ssh-rsa', 'ssh-ed25519',
].join('|');

/** PEM 私钥块 / PEM private key blocks. */
const PEM_PRIVATE = String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`;

/** PEM 公钥块 / PEM public key blocks（默认放行）. */
const PEM_PUBLIC = String.raw`-----BEGIN PUBLIC KEY-----[\s\S]{0,8192}?-----END PUBLIC KEY-----`;

/** 高权限密码关键词 / Privileged password keywords. */
const PRIVILEGED_KEYWORDS = 'root|ssh|admin|super|payment|pay|passphrase|管理员|超级|支付';

/**
 * 基础规则表 / Base rule table.
 *
 * 顺序即优先级：结构化字段 → 证件 → 凭证 → 地址 → 网络。
 * `level` 决定命中后的处置，`kind` 只用于日志。
 *
 * Order is priority. `level` decides the action; `kind` only labels the log.
 */
const BASE_RULES = [
  // ========== 私钥与高权限密钥：BLOCK ==========
  {
    id: 'pem-private-key',
    level: LEVELS.block,
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: new RegExp(PEM_PRIVATE, 'g'),
  },
  {
    id: 'ssh-private-key',
    level: LEVELS.block,
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: /(?<![\w-])ssh-(?:rsa|ed25519|dss)\s+AAAA[A-Za-z0-9+/=]{20,}/g,
  },
  {
    id: 'key-prefix',
    level: LEVELS.block,
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: new RegExp(String.raw`(?<![\w-])${KEY_PREFIX}[A-Za-z0-9_+=/-]{8,}`, 'g'),
  },
  {
    id: 'jwt',
    level: LEVELS.block,
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    // 示例 JWT 由白名单放行。
    re: /(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    validate: (value) => !isWhitelistedValue(value),
  },
  {
    id: 'bearer',
    level: LEVELS.block,
    kind: HIT_KINDS.secret,
    to: PLACEHOLDERS.secret,
    re: /((?:Authorization\s*[:=]\s*)?Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/gi,
    keepGroup: 1,
  },

  // ========== 高权限密码：BLOCK ==========
  {
    id: 'privileged-password',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.secret,
    // root/ssh/admin/payment/passphrase 等关键词，取值为高熵串。
    re: new RegExp(String.raw`((?:${PRIVILEGED_KEYWORDS})[^\n]{0,24}?(?:password|passwd|pwd|密码|口令|passphrase)\s*(?:=>|[:=：])\s*["'\`]?)([^\s"'\`,;)}\]]{6,})`, 'gi'),
    keepGroup: 1,
  },

  // ========== 身份与支付：BLOCK ==========
  {
    id: 'cn-id-card',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
    validate: (value) => !isPlaceholderNumber(value),
  },
  {
    id: 'bank-card',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)(?:\d{4}[ -]?){3,4}\d{0,3}(?!\d)/g,
    validate: validateBankCard,
  },
  {
    id: 'cvv',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /((?:CVV2?|CVC2?|安全码|校验码)\s*[:=：]?\s*)(\d{3,4})(?!\d)/gi,
    keepGroup: 1,
  },
  {
    id: 'passport',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.privacy,
    re: /(?<![\w])(?:E\d{8}|[GH]\d{8}|[A-Z]\d{8,10})(?![\w])/g,
    validate: (value) => !isWhitelistedValue(value) && !isExcluded(value),
  },

  // ========== 联系类：BLOCK（新增） ==========
  {
    id: 'cn-mobile',
    level: LEVELS.block,
    kind: HIT_KINDS.contact,
    to: PLACEHOLDERS.privacy,
    re: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
    validate: (value) => !isPlaceholderNumber(value),
  },
  {
    id: 'email',
    level: LEVELS.block,
    kind: HIT_KINDS.email,
    to: PLACEHOLDERS.email,
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    validate: (value) => !isWhitelistedValue(value),
  },
  {
    id: 'social-id',
    level: LEVELS.block,
    kind: HIT_KINDS.social,
    to: PLACEHOLDERS.social,
    re: /(?:wxid_[A-Za-z0-9_-]{6,}|(?:(?:微信|QQ|qq|wx|wechat|weixin)\s*(?:号|ID|id)?\s*[:：=]?\s*)[A-Za-z0-9_-]{5,20})/g,
    validate: (value) => !/^(?:微信|QQ|qq|wx|wechat|weixin)\s*(?:号|ID|id)?$/i.test(value),
  },

  // ========== 一次性凭证：BLOCK（新增） ==========
  {
    id: 'one-time-code',
    level: LEVELS.block,
    kind: HIT_KINDS.otp,
    to: PLACEHOLDERS.otp,
    re: /((?:验证码|短信码|校验码|动态码|口令|verify|verification|otp|totp|one[- ]?time(?: code| password)?|2fa|code)\s*[:：=是为]?\s*)(\d{4,6})(?!\d)/gi,
    keepGroup: 1,
  },

  // ========== 位置信息：BLOCK（新增） ==========
  {
    id: 'home-address',
    level: LEVELS.block,
    kind: HIT_KINDS.address,
    to: PLACEHOLDERS.home,
    re: /(?:[\u4e00-\u9fff]{2,8}(?:省|自治区|特别行政区))?[\u4e00-\u9fff]{2,8}(?:市|自治州|地区)[\u4e00-\u9fff]{2,8}(?:区|县|旗)[\u4e00-\u9fff0-9]{0,24}?(?:路|街|道|巷|弄|村|镇|小区|花园|公寓|大厦|号楼|栋|单元|室)[\u4e00-\u9fff0-9]{0,24}/g,
  },
  {
    id: 'home-address-street',
    level: LEVELS.block,
    kind: HIT_KINDS.address,
    to: PLACEHOLDERS.home,
    re: /(?:\d{6}\s*)?[\u4e00-\u9fff]{2,12}(?:路|街|大道|巷)[0-9]{1,5}号[\u4e00-\u9fff0-9]{0,24}(?:室|层|楼|单元|栋|座|号)/g,
  },

  // ========== 普通密码：BLOCK（新增） ==========
  {
    id: 'kv-credential',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    re: new RegExp(String.raw`${KV_PREFIX}${KV_VALUE}`, 'gi'),
    keepGroup: 1,
  },
  {
    id: 'service-password',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    re: /((?:adb|server|database|db|mysql|postgres|redis|wifi|wi-fi|router)[^\n]{0,24}?(?:password|passwd|pwd|密码|口令)\s*[:=：]\s*)["'`]?[^\s"'`,;]{3,}/gi,
    keepGroup: 1,
  },
  {
    id: 'env-credential',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    re: /(^|\n)(\s*(?:export\s+|ENV\s+)?[A-Z][A-Z0-9_]{2,}\s*(?:=>|[:=])\s*["'`]?)([^\s"'`,;#]{4,})/g,
    keepGroup: 2,
  },

  // ========== 高熵兜底：BLOCK ==========
  {
    id: 'high-entropy',
    level: LEVELS.block,
    kind: HIT_KINDS.entropy,
    to: PLACEHOLDERS.secret,
    re: /(?<![\w+/=-])[A-Za-z0-9+/_-]{24,}(?![\w+/=-])/g,
    validate: isHighEntropy,
  },

  // ========== 会话凭证：MASK ==========
  {
    id: 'cookie-session',
    level: LEVELS.mask,
    kind: HIT_KINDS.account,
    to: PLACEHOLDERS.cred,
    re: /((?:cookie|set-cookie|session|sid|connect\.sid|jsessionid|phpsessid)\s*[:=]\s*)[^\s;,\n]{8,}/gi,
    keepGroup: 1,
  },
  {
    id: 'temp-login-link',
    level: LEVELS.mask,
    kind: HIT_KINDS.cred,
    to: PLACEHOLDERS.cred,
    re: /\bhttps?:\/\/[^\s"'<>]{6,}?\?(?:[^\s"'<>]*?(?:token|ticket|code|sign|sig|expires|key|apikey|pwd)=)[^\s"'<>]{6,}/gi,
  },
  {
    id: 'url-credential',
    level: LEVELS.mask,
    kind: HIT_KINDS.cred,
    to: PLACEHOLDERS.cred,
    re: /((?:[?&](?:token|apikey|api_key|access_token|auth|pwd|password|secret|sessionid)=))[^&\s#"']{3,}/gi,
    keepGroup: 1,
  },

  // ========== 交易信息：MASK ==========
  {
    id: 'trade-no',
    level: LEVELS.mask,
    kind: HIT_KINDS.trade,
    to: PLACEHOLDERS.trade,
    re: /((?:订单号|订单编号|流水号|交易号|支付单号|order(?:\s*(?:id|no|number))?|transaction(?:\s*id)?|trade(?:\s*no)?|payment[._-]?id)\s*[:=：]?\s*)[A-Za-z0-9_-]{8,}/gi,
    keepGroup: 1,
  },

  // ========== 证书与指纹：MASK ==========
  {
    id: 'cert-info',
    level: LEVELS.mask,
    kind: HIT_KINDS.cert,
    to: PLACEHOLDERS.cert,
    re: /((?:证书序列号|serial(?:\s*number)?|序列号)\s*[:=：]\s*)[0-9A-Fa-f:\s]{8,}|((?:subject|DN|证书主题)\s*[:=：]\s*)[^\n]{8,}/gi,
    keepGroup: 1,
  },
  {
    id: 'key-fingerprint',
    level: LEVELS.mask,
    kind: HIT_KINDS.fingerprint,
    to: PLACEHOLDERS.fingerprint,
    re: /((?:fingerprint|指纹|SHA256|SHA-256|SHA1|SHA-1)\s*[:=：]?\s*)(?:(?:[0-9A-Fa-f]{2}:){15,31}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{40}(?![0-9A-Fa-f])|[0-9A-Fa-f]{64}(?![0-9A-Fa-f]))/gi,
    keepGroup: 1,
  },

  // ========== 本地路径：MASK ==========
  {
    id: 'local-path',
    level: LEVELS.mask,
    kind: HIT_KINDS.path,
    to: PLACEHOLDERS.path,
    re: /(?:[A-Za-z]:[\\/][^\s"'<>|,;)\]}]+|\/storage\/[^\s"'<>|,;)\]}]*|\/sdcard\/[^\s"'<>|,;)\]}]*|\/data\/[^\s"'<>|,;)\]}]*|\/root\/[^\s"'<>|,;)\]}]*|\/home\/[^\s"'<>|,;)\]}]+|\/Users\/[^\s"'<>|,;)\]}]+)/g,
  },

  // ========== 设备标识：MASK ==========
  {
    id: 'device-id',
    level: LEVELS.mask,
    kind: HIT_KINDS.device,
    to: PLACEHOLDERS.device,
    re: /\b(?:[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{16})\b/g,
    validate: (value) => !isExcluded(value) && !/^\d+$/.test(value.replace(/-/g, '')),
  },

  // ========== 网络：MASK ==========
  {
    id: 'mac-address',
    level: LEVELS.mask,
    kind: HIT_KINDS.mac,
    to: PLACEHOLDERS.mac,
    re: /(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:.-])/g,
    validate: (value) => !/^(?:00[:-]){5}00$/.test(value),
  },
  {
    id: 'net-ipv6',
    level: LEVELS.mask,
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.net,
    // 标准 IPv6：完整八组、压缩写法（::）、以及带内嵌 IPv4 的形式。
    // Standard IPv6: full form, compressed (::), and IPv4-embedded.
    re: /(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?::[0-9]{1,3}(?:\.[0-9]{1,3}){3})?(?![\w:])/g,
    validate: (value) => value !== '::1' && value !== '::',
    // ULA（fc00::/7）归入内网。
    toFor: (value) => (/^(?:f[cd])/i.test(value) ? PLACEHOLDERS.lan : PLACEHOLDERS.net),
  },
  {
    id: 'lan-ipv4',
    level: LEVELS.mask,
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.lan,
    re: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3})\b/g,
  },
  {
    id: 'net-ipv4',
    level: LEVELS.mask,
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

/** 去掉分隔符 / Strip separators from a formatted number. */
function digitsOnly(value) {
  return value.replace(/[\s-]/g, '');
}

/**
 * 银行卡校验 / Bank card validation.
 * 16–19 位、Luhn 通过、排除重复与递增序列。
 */
export function validateBankCard(value) {
  const digits = digitsOnly(value);
  if (!/^\d{16,19}$/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  if (isAscending(digits)) return false;
  if (isWhitelistedValue(digits)) return false;
  if (isExcluded(digits)) return false;
  return luhn(digits);
}

/** 递增或递减序列 / Ascending or descending digit run. */
function isAscending(value) {
  let ascending = true;
  let descending = true;
  for (let index = 1; index < value.length; index += 1) {
    const delta = value.charCodeAt(index) - value.charCodeAt(index - 1);
    if (delta !== 1) ascending = false;
    if (delta !== -1) descending = false;
  }
  return ascending || descending;
}

/** 样板证件号：全同、递增、白名单 / Sample identity numbers. */
function isPlaceholderNumber(value) {
  if (/^(\d)\1+$/.test(value)) return true;
  if (isAscending(value.replace(/[Xx]$/, ''))) return true;
  return isWhitelistedValue(value);
}

/**
 * 白名单判定 / Whitelist test.
 *
 * 规格要求白名单优先级最高，命中即跳过所有规则。但整段文本的白名单判定只
 * 对短文本生效：一段 4KB 代码里出现 `xxxx` 或 `xxx` 不该让整段免检。
 *
 * The whitelist outranks every rule, but the whole-text check applies only to
 * short inputs: a 4 KB code block containing `xxxx` must not exempt the whole
 * block from scanning.
 */
export function isWhitelistedValue(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  const lowered = value.toLowerCase();

  // 长文本不做整段白名单判定，避免子串误伤。
  if (value.length > 256) return false;

  // 精确等于白名单项。
  if (DEFAULT_WHITELIST.some((token) => lowered === token.toLowerCase())) return true;

  // 短文本允许子串匹配，但白名单项自身必须足够长，否则 `xxx` 会吃掉一切。
  return DEFAULT_WHITELIST.some((token) => token.length >= 6 && lowered.includes(token.toLowerCase()));
}

/** 回环、广播、示例地址不视为部署机密 / Loopback, broadcast, sample addresses. */
function isMaskableIp(value) {
  return value !== '127.0.0.1'
    && value !== '0.0.0.0'
    && value !== '255.255.255.255'
    && !value.startsWith('192.0.2.')
    && !value.startsWith('198.51.100.')
    && !value.startsWith('203.0.113.');
}

/**
 * 排除项 / Exclusions.
 * 端口、版本号、哈希、UUID、颜色值、数学算式、寄存器地址。
 */
export function isExcluded(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  // 端口
  if (/^\d{1,5}$/.test(value)) {
    const port = Number(value);
    if (port >= 1 && port <= 65535) return true;
  }
  // 版本号
  if (/^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/i.test(value)) return true;
  // 十六进制哈希（md5/sha1/sha256/sha512）与 git commit hash
  if (/^[0-9a-f]{7,128}$/i.test(value) && [32, 40, 64, 128].includes(value.length)) return true;
  if (/^[0-9a-f]{7,8}$/i.test(value)) return true;
  // UUID
  if (/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value)) return true;
  // 颜色值
  if (/^#(?:[0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(value)) return true;
  // 寄存器地址
  if (/^0x[0-9a-f]{1,16}$/i.test(value)) return true;
  // 数学算式
  if (/^[\d\s+\-*/%().=<>!&|^~]+$/.test(value) && /[+\-*/%]/.test(value)) return true;
  return false;
}

/**
 * 高熵判定 / High-entropy test.
 * 长度 ≥ 24，至少三类字符，去重 ≥ 12，香农熵 ≥ 3.0。
 */
export function isHighEntropy(value) {
  if (typeof value !== 'string' || value.length < 24) return false;
  if (isExcluded(value)) return false;
  if (isWhitelistedValue(value)) return false;
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/\d/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  if (classes < 3) return false;
  if (new Set(value).size < 12) return false;
  return shannonEntropy(value) >= 3.0;
}

/** 香农熵（每字符比特数）/ Shannon entropy in bits per character. */
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
    level: LEVELS.mask,
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.url,
    re: new RegExp(`\\b(?:https?:\\/\\/)?(?:[a-z0-9-]+\\.)+(?:${internal.join('|')})\\b[A-Za-z0-9/._~:%?#@!$&'*+,;=-]*`, 'gi'),
  });
  if (level === true || level === 'all') {
    rules.push({
      id: 'domain',
      level: LEVELS.mask,
      kind: HIT_KINDS.net,
      to: PLACEHOLDERS.url,
      re: new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${PUBLIC_SUFFIXES.join('|')})\\b`, 'gi'),
      validate: (value) => !isWhitelistedValue(value),
    });
  }
  return rules;
}

/** 可选规则 / Optional rules. */
function optionalRules(config) {
  const rules = [...urlRules(config)];
  if (config.maskPublicKeys === true) {
    rules.push({
      id: 'pem-public-key',
      level: LEVELS.mask,
      kind: HIT_KINDS.secret,
      to: PLACEHOLDERS.secret,
      re: new RegExp(PEM_PUBLIC, 'g'),
    });
  }
  if (config.maskDbCredentials !== false) {
    rules.push({
      id: 'db-credential',
      level: LEVELS.block,
      kind: HIT_KINDS.password,
      to: PLACEHOLDERS.db,
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle|clickhouse):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'<>]*/gi,
    });
  }
  return rules;
}

/**
 * 组装规则表 / Assemble the rule table.
 *
 * @param {object} config 归一化配置 / normalized config
 * @param {object[]} [extraRules] 额外规则（住址、病历、姓名+证件）/ extra rules
 */
export function buildRules(config, extraRules = []) {
  const rules = [...extraRules, ...BASE_RULES, ...optionalRules(config)];
  return rules.filter((rule) => !config.disabledRules?.includes(rule.id));
}
