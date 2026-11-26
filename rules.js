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

/**
 * 占位符词表 / Placeholder vocabulary.
 *
 * **一种语义一个占位符。** 早先手机号、身份证、银行卡、护照、社保卡、病历共用
 * `{{PRIVACY_ID}}`，只靠 `_2`、`_3` 序号区分——序号是插入顺序编号，不携带语义，
 * 读日志的人看不出 `{{PRIVACY_ID_2}}` 是手机号还是卡号；同一段文本里两个不同
 * 类型的值谁拿到 `_2` 还取决于规则先后。
 *
 * **One placeholder per meaning.** Phone, identity card, bank card, passport,
 * social-security card, and medical record all shared `{{PRIVACY_ID}}` and were
 * told apart only by insertion-order suffixes, which carry no meaning: a reader
 * cannot tell whether `{{PRIVACY_ID_2}}` is a phone or a card, and which one gets
 * `_2` depends on rule order.
 */
/**
 * 数字串分隔符 / Separators allowed inside long numeric identifiers.
 *
 * 手机号、身份证、银行卡常被空格、连字符、点、下划线、斜杠、间隔号拆开书写
 * （`1-3-8-0-0...`、`6222 0212 0201 2345 678`）。规则正则把这些符号当作
 * 可选分隔符，去掉后按原形状判定，命中即替换整段（含分隔符）。
 * 只覆盖这些明确的标点，不做全局 `\D` 移除，避免误伤 `1.2.3`、`12:30` 等。
 */
const NUM_SEP = '[ .\\-_/·]';
/** 去掉数字串里的允许分隔符，供 validate 归一后判定。 */
const stripNumSep = (s) => s.replace(/[ .\-_/·]/g, '');

export const PLACEHOLDERS = Object.freeze({
  secret: '{{SECRET_TOKEN}}',
  /** 通用身份信息兜底 / generic identity fallback. */
  privacy: '{{PRIVACY_ID}}',
  /** 身份证 / national identity card. */
  idCard: '{{ID_CARD}}',
  /** 手机号 / mobile phone number. */
  phone: '{{PHONE_NO}}',
  /** 银行卡 / bank card number. */
  bankCard: '{{BANK_CARD}}',
  /** 护照 / passport number. */
  passport: '{{PASSPORT_NO}}',
  /** 社保卡 / social security card. */
  socialCard: '{{SOCIAL_CARD}}',
  /** 病历与诊断 / medical record and diagnosis. */
  medical: '{{MEDICAL_INFO}}',
  /** 姓名+证件 / name paired with a document. */
  nameId: '{{NAME_AND_ID}}',
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
  plate: '{{PLATE_NO}}',
  /** 余额与金额 / account balance and payment amount. */
  balance: '{{BALANCE_AMOUNT}}',
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
  // 样板测试数据。
  //
  // 这里刻意**不**收录常见的「示例手机号」与「示例身份证号」：13800138000
  // 既是文档示例也是真实在用的号段，把它放进白名单会让真实号码逃过脱敏。
  // 样板数据的识别交给 `isPlaceholderNumber`（全同、递增、与示例同形），
  // 而不是靠一张号码表。
  //
  // Deliberately excludes common "sample phone numbers" and "sample ID
  // numbers": 13800138000 is both a documentation example and a real number in
  // use, so listing it would let a real number through. Placeholder data is
  // recognised by `isPlaceholderNumber` (uniform, ascending, example-shaped)
  // rather than by a number table.
  '6222000000000000', '4111111111111111', '5555555555554444',
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
  plate: '车牌号',
  balance: '资金信息',
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
 *
 * 中文标签常直接跟取值而不加分隔符（`密码Abc@123456`），因此中文键名后的
 * 分隔符改为**可选**；英文键名仍要求分隔符，否则 `tokenize something` 会被
 * 误判。
 *
 * A closing quote after the key is required for JSON. Compound keys accept dot,
 * underscore, and hyphen. Chinese labels often carry no separator
 * (`密码Abc@123456`), so the separator is optional after a Chinese key while
 * still required after an English one.
 */
const KV_KEY_EN = String.raw`(?:password|passwd|pwd|secret|token|key|apikey|api[._-]?key|accesskey|access[._-]?key|access[._-]?token|auth|authorization|bearer|sshkey|ssh[._-]?key|private[._-]?key|passphrase|client[._-]?secret|storePassword|keyPassword|pkcs12(?:Password)?|signaturePassword|credential)`;

const KV_KEY_ZH = String.raw`(?:账号|帐号|用户名|密码|口令|数据库密码|wifi密码|支付密钥|密钥|pin码)`;

/**
 * 前缀必须是**一个**捕获组 / The prefix must be a single capture group.
 *
 * 早先写成 `(?:((?:EN))|((?:ZH)))`：两个备选各带一个捕获组，于是英文前缀是
 * 第 1 组、中文前缀是第 2 组、取值退到第 3 组。`keepGroup:1` 的取值逻辑因此
 * 在中文键上取到前缀本身，输出成 `undefined{{CRED_CODE}}`——一段真的会写进
 * session 的坏字符串。现在把两种键名放进同一个外层捕获组，取值恒为第 2 组。
 *
 * The earlier shape gave each alternative its own capture group, so Chinese keys
 * put the prefix in group 2 and the value in group 3; `keepGroup:1` then read the
 * prefix as the value and emitted `undefined{{CRED_CODE}}`. Both key styles now
 * live inside one outer group, making the value always group 2.
 */
const KV_PREFIX = String.raw`((?:(?<![A-Za-z0-9_.?&-])(?:${KV_KEY_EN})\s*["'` + '`' + String.raw`]?\s*(?:=>|[:=：])\s*["'` + '`' + String.raw`]?|(?<![?&])(?:${KV_KEY_ZH})\s*(?:是|为|＝|=>|[:=：])?\s*["'` + '`' + String.raw`]?))`;

/**
 * 取值终止符 / Value terminators.
 *
 * 分隔符后的空白由前缀吸收，取值从第一个非空白字符开始，因此
 * `密码: P@ssw0rd` 会保留冒号后的空格。
 *
 * Whitespace after the separator belongs to the prefix, so the value starts at
 * the first non-space character and `密码: P@ssw0rd` keeps its space.
 */
const KV_VALUE = String.raw`([^\s"'` + '`' + String.raw`,;，。；、！？)}\]]{3,})`;

/**
 * 文档占位词 / Documentation placeholder words.
 *
 * `key=value`、`token=string` 是文档里最常见的占位写法，不是真实凭据。
 * 只有取值正好是这些词之一（整词相同）时才放行，真实长串不受影响。
 *
 * `key=value` and `token=string` are the most common documentation placeholders,
 * not real credentials. Only an exact whole-word match is waved through.
 */
const DOC_PLACEHOLDER_VALUES = new Set([
  'value', 'string', 'number', 'boolean', 'text', 'true', 'false', 'null',
  'password', 'passwd', 'secret', 'token', 'key', 'example', 'sample',
  'foo', 'bar', 'baz', 'xxx', 'yyy', 'zzz', 'todo', 'tbd', 'changeme',
  '是', '为', '的', '吗', '呢', '吧', '了', '和', '或', '与', '在', '有',
]);

/**
 * 中文密码标签后允许的**连接词** / Chinese connectors allowed after a password label.
 *
 * `密码Abc@123456`（直接相邻）与 `密码是 Zhang@2024`（中间有「是」/「为」）
 * 都是真实写法。为防止把 `密码是` 当成「密码」取值为 `是`，连接词必须从取值里
 * 去掉后再判空白值。
 *
 * Both `密码Abc@123456` and `密码是 Zhang@2024` are real spellings. To avoid
 * reading `是` as the value, connectors are stripped before the blank check.
 */
const ZH_CONNECTORS = /^(?:是|为|的|＝|[:=：]\s*)+/;

/**
 * 固定前缀密钥 / Fixed-prefix keys.
 *
 * 前缀按长度降序排列，长的先匹配，避免 `sk-` 抢先吃掉 `sk-proj-` 的前半段。
 * 前缀本身必须后接足够长的密钥体，否则 `AKIA` 这类短前缀会把整个值只换掉
 * 开头四个字符，留下可读的剩余部分。
 *
 * Prefixes are ordered longest-first so `sk-` cannot claim the head of
 * `sk-proj-`. Each prefix must be followed by a substantial body, otherwise a
 * short prefix such as `AKIA` replaces four characters and leaves the rest
 * readable.
 */
const KEY_PREFIX = [
  'github_pat_', 'sk-proj-', 'sk-ant-', 'sk_live_', 'sk_test_', 'rk_live_', 'rk_test_', 'whsec_',
  'glpat-', 'xox[baprs]-', 'ssh-ed25519', 'ssh-rsa',
  'AKIA', 'ASIA', 'LTAI', 'AKID', 'AIza', 'ghp_', 'gho_', 'sk-', 'hf_', 'npm_',
].join('|');

/** PEM 私钥块 / PEM private key blocks. */
const PEM_PRIVATE = String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`;

/** PEM 公钥块 / PEM public key blocks（默认放行）. */
const PEM_PUBLIC = String.raw`-----BEGIN PUBLIC KEY-----[\s\S]{0,8192}?-----END PUBLIC KEY-----`;

/** 高权限密码关键词 / Privileged password keywords. */
const PRIVILEGED_KEYWORDS = 'root|ssh|admin|super|payment|pay|passphrase|管理员|超级|支付';

/**
 * 卡号标签 / Card-number labels.
 *
 * 三类：卡种词、发卡机构（全称与常用简称）、卡组织。机构名是实测补上的——
 * `邮政6221…`、`银联6221…`、`农信6221…` 先前全部漏检，因为标签表只有
 * 「卡号/银行卡/信用卡」这几个词。
 *
 * 顺序要求：长的放前面，避免 `中国工商银行` 被 `中国银行` 之外的短词截断
 * （本例中 `工商银行` 与 `中国银行` 不重叠，但 `农村信用社`/`农商行` 与
 * `农信` 会互相竞争，长词优先才能匹配完整标签）。
 *
 * Three groups: card-type words, issuing banks (full names and common short
 * forms), and card schemes. The bank names were added after measurement: labels
 * such as 邮政/银联/农信 all slipped through when only 卡号/银行卡 existed.
 * Longest-first ordering keeps a short abbreviation from truncating a full name.
 */
const CARD_TYPE_LABELS = '银行卡号?|卡号|信用卡号?|储蓄卡号?|借记卡号?|银联卡|credit\\s*card(?:\\s*number)?|card\\s*(?:no|number)|debit\\s*card(?:\\s*number)?|bank\\s*card';
const CARD_SCHEME_LABELS = 'unionpay|visa|mastercard|maestro|jcb|amex|american\\s*express|discover';
const CARD_BANK_LABELS = [
  // 全称
  '中国工商银行', '中国建设银行', '中国农业银行', '中国银行', '交通银行', '招商银行',
  '中国邮政储蓄银行', '邮政储蓄', '农村信用社', '农村商业银行', '农业发展银行',
  '浦发银行', '中信银行', '民生银行', '兴业银行', '光大银行', '华夏银行', '广发银行',
  '平安银行', '浙商银行', '渤海银行', '恒丰银行', '北京银行', '上海银行', '江苏银行',
  '宁波银行', '南京银行', '杭州银行', '徽商银行', '中原银行', '长沙银行', '成都银行',
  '重庆银行', '贵阳银行', '西安银行', '兰州银行', '青岛银行', '苏州银行', '郑州银行',
  // 常用简称
  '工商银行', '建设银行', '农业银行', '邮政银行', '邮储银行', '农商行', '信用社',
  '工行', '建行', '农行', '中行', '交行', '招行', '邮储', '农信', '邮政', '银联',
  '浦发', '中信', '民生', '兴业', '光大', '华夏', '广发',
].sort((a, b) => b.length - a.length).join('|');

const CARD_LABEL = `${CARD_TYPE_LABELS}|${CARD_BANK_LABELS}|${CARD_SCHEME_LABELS}`;

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
    // 前缀必须整体分组，否则 `(?<![\w-])` 只约束第一个备选，其余前缀会
    // 从词中任意位置匹配，且密钥体只跟着最后一个备选。
    //
    // The prefix must be wrapped in a group: without it the lookbehind binds to
    // the first alternative only, and the body class attaches to the last one.
    re: new RegExp(String.raw`(?<![\w-])(?:${KEY_PREFIX})[A-Za-z0-9_+=/-]{8,}`, 'g'),
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
    to: PLACEHOLDERS.idCard,
    re: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
    validate: (value) => !isPlaceholderNumber(value),
  },
  {
    id: 'cn-id-card-spaced',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.idCard,
    // 身份证常被分组书写（`1101011990 0307 4513`、`110101 1990 0307 4513`）。
    // 去掉空格后用同一形状判定，命中就把整段（含空格）替换掉。
    //
    // Identity numbers are often grouped (`1101011990 0307 4513`). Strip the
    // spacing, test the same shape, and replace the whole spaced run.
    re: /(?<![\dA-Za-z])\d(?:[ .\-_/·\t]?\d){16}[ .\-_/·\t]?[\dXx](?![\dA-Za-z])/g,
    validate: (value) => {
      if (!/[ .\-_/·\t]/.test(value)) return false; // 无分隔符交给 cn-id-card
      const bare = value.replace(/[ .\-_/·\t]/g, '');
      if (!/^[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]$/.test(bare)) return false;
      return !isPlaceholderNumber(bare);
    },
  },
  {
    id: 'bank-card',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.bankCard,
    re: /(?<!\d)\d(?:[ .\-_/·]?\d){14,18}(?!\d)/g,
    validate: validateBankCard,
  },
  {
    id: 'bank-card-labelled',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.bankCard,
    // 带标签的卡号 / a card number that carries a label.
    //
    // 无标签的 16–19 位数字靠 Luhn 校验位排除噪声，这个取舍是对的：任意长数字
    // 都可能是订单号或设备号。但一旦用户写了「卡号」「银行卡」「credit card」，
    // 语义已经明确——此时**再要求 Luhn 通过就是漏检**。实测
    // `卡号6221885935650739436`（19 位、校验位不合）被原样放行，一个真实卡号
    // 就这样进了模型请求。
    //
    // 因此这条规则只认带标签的形态，不做 Luhn 校验；标签之间的取值必须是
    // 13–19 位纯数字（可含空格/连字符分组），并且排除样板号与端口形态。
    //
    // A bare 16–19 digit run is gated by Luhn, which is the right trade-off:
    // any long number could be an order or device id. But once a label is present
    // the meaning is explicit, and still demanding Luhn turns a real card into a
    // miss — verified with `卡号6221885935650739436` (19 digits, bad check digit)
    // passing through untouched. This rule therefore trusts the label and skips
    // Luhn, while still rejecting sample cards and port-shaped values.
    // 标签必须自己成为**第 1 个捕获组**：`keepGroup` 保留的是这一组的内容。
    // 早先写成非捕获的 `(?:标签)`，第 1 组是卡号，于是替换结果变成
    // `6221885935650739436{{BANK_CARD}}`——标签被吃掉、号码留在原地，
    // 恰好把最该隐藏的部分暴露出来。
    //
    // The label must be capture group 1, because `keepGroup` keeps that group. A
    // non-capturing label made group 1 the card number, so the result was
    // `6221885935650739436{{BANK_CARD}}`: the label vanished and the number itself
    // stayed in clear text — the worst possible outcome.
    re: new RegExp(String.raw`((?:${CARD_LABEL})\s*[:：=]?\s*["'\x60]?)((?:\d[ -]?){12,18}\d)(?![\d])`, 'gi'),
    keepGroup: 1,
    validate: (whole) => {
      // `validate` 收到的是**完整匹配**（标签+号码）。第 2 组才是号码。
      const match = /((?:\d[ -]?){12,18}\d)\s*$/.exec(whole);
      if (match === null) return false;
      const digits = match[1].replace(/[ -]/g, '');
      if (!/^\d{13,19}$/.test(digits)) return false;
      if (isPlaceholderNumber(digits)) return false;
      if (isTestCard(digits)) return false;
      if (/^(\d)\1+$/.test(digits)) return false;
      if (isAscending(digits)) return false;
      if (isWhitelistedValue(digits)) return false;
      if (isExcluded(digits)) return false;
      return true;
    },
  },
  {
    id: 'cvv',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.bankCard,
    re: /((?:CVV2?|CVC2?|安全码|校验码)\s*[:=：]?\s*)(\d{3,4})(?!\d)/gi,
    keepGroup: 1,
  },
  {
    id: 'passport',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.passport,
    re: /(?<![\w])(?:E\d{8}|[GH]\d{8}|[A-Z]\d{8,10})(?![\w])/g,
    validate: (value) => !isWhitelistedValue(value) && !isExcluded(value) && !isLikelyVersion(value),
  },
  {
    id: 'social-security-card',
    level: LEVELS.block,
    kind: HIT_KINDS.privacy,
    to: PLACEHOLDERS.socialCard,
    // 社保卡号 / social security card number.
    //
    // 常见形态：18 位纯数字，或「字母前缀 + 数字」的卡面号（D1234567890123）。
    // 纯数字分支必须要求前导关键词，否则会与身份证、银行卡互相吃掉；
    // 带字母前缀的分支形状足够独特，可直接识别。
    //
    // Common shapes: eighteen digits, or a letter-prefixed card number. The
    // digit-only branch requires a leading keyword, or it would compete with the
    // identity and bank-card rules; the letter-prefixed branch is distinctive
    // enough on its own.
    re: /(?:社保卡号?|社会保障卡号?|医保卡号?|social\s*security(?:\s*(?:card|number))?\s*[:：=]?\s*)\s*(?:\d{9,18}(?!\d)|[A-Z]\d{8,13}(?!\w))/gi,
    keepGroup: undefined,
  },
  {
    id: 'license-plate',
    level: LEVELS.mask,
    kind: HIT_KINDS.plate,
    to: PLACEHOLDERS.plate,
    // 中国车牌 / Chinese vehicle plate.
    //
    // 普通蓝牌：省份简称 + 发牌代号 + 5 位；新能源绿牌有两种写法——小型车
    // `粤BD12345`（D/F 紧跟在发牌代号后），大型车 `粤B12345D`（D/F 在末尾）。
    // 使领馆、警用等用后缀字母。省份简称限定为真实存在的 31 个，避免把
    // 「粤B」这类普通字母组合误判。
    //
    // Ordinary plates are province + letter + five characters. New-energy plates
    // have two shapes: small cars put D/F right after the region letter, large
    // cars put D/F at the end. Both are accepted. The province set is explicit
    // so unrelated two-character runs are not claimed.
    re: /(?:[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-HJ-NP-Z](?:[A-HJ-NP-Z0-9]{4}[挂学警港澳领使试超]|[A-HJ-NP-Z0-9]{5}|[DF][A-HJ-NP-Z0-9]{5}|[0-9]{5}[DF]))(?![A-Za-z0-9\u4e00-\u9fff])/g,
  },

  // ========== 联系类：BLOCK（新增） ==========
  {
    id: 'cn-mobile',
    level: LEVELS.block,
    kind: HIT_KINDS.contact,
    to: PLACEHOLDERS.phone,
    // 连续 11 位，或带空格/连字符分组（`138-0013-8002`、`138 0013 8002`）。
    // 国际区号 `+86` 由 `(?!\d)` 左界保证不会被吞进号码。
    //
    // Eleven digits, or grouped with spaces/hyphens (`138-0013-8002`,
    // `138 0013 8002`). The `+86` country code is left outside by the boundary.
    // 号码允许分组空格/短横/点，且可带 +86/0086 国际区号（国家码本身不替换）。
    // 另容许一个前导 `0`：电话本与老式表单常写成 `0139…`（长途冠码习惯）。
    //
    // Accept grouped spaces, hyphens, or dots and optional +86/0086; the country
    // code stays outside the replacement. A single leading `0` is tolerated too,
    // because address books and older forms write `0139…`.
    re: new RegExp(String.raw`(?<![0-9０-９])(?:(?:\+?86|0086)[ .\-_/·]?)?[（(]?[0０]?[1１][ .\-_/·]?[3-9３-９][ .\-_/·]?[0-9０-９][）)]?(?:[ .\-_/·]?[0-9０-９]){8}(?![0-9０-９])`, 'g'),
    validate: (value) => {
      const normalized = value.normalize('NFKC');
      const local = normalized
        .replace(/^(?:(?:\+?86|0086)[ .\-_/·]?)?/, '')
        .replace(/^0(?=1[3-9])/, '');
      const digits = local.replace(/\D/g, '');
      return digits.length === 11 && !isPlaceholderNumber(digits);
    },
  },
  {
    id: 'email',
    level: LEVELS.block,
    kind: HIT_KINDS.email,
    to: PLACEHOLDERS.email,
    // `user@host`（无点域名）不是邮箱，而是 scp/ssh 目标或本地账号：`deploy@host`、
    // `host.internal` 都被误判成邮箱并遮蔽成 `{{EMAIL_ADDR}}` 后，运维命令就废了。
    // TLD 分支里 `internal`/`local`/`lan` 等内网后缀更是内部主机名而非邮箱。
    //
    // `user@host` with no dotted domain is an ssh/scp target, not an email, and
    // internal hostnames (`host.internal`) are infrastructure, not mailboxes;
    // masking either to `{{EMAIL_ADDR}}` destroys an ops command.
    re: /(?<!\bscp\s)(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?!:)/gi,
    validate: (value) => !isWhitelistedValue(value)
      && !/\.(?:internal|local|localhost|lan|corp|intra|private|svc|home)$/i.test(value),
  },
  {
    id: 'social-id',
    level: LEVELS.block,
    kind: HIT_KINDS.social,
    to: PLACEHOLDERS.social,
    // `wxid_xxx` 自成一类：没有可保留的标签，整串都是账号。
    // A `wxid_` handle has no label worth keeping; the whole run is the account.
    re: /wxid_[A-Za-z0-9_-]{6,}/g,
    validate: (value) => !/^(?:微信|QQ|qq|wx|wechat|weixin)\s*(?:号|ID|id)?$/i.test(value),
  },
  {
    id: 'social-id-labelled',
    level: LEVELS.block,
    kind: HIT_KINDS.social,
    to: PLACEHOLDERS.social,
    // 标签 + 账号，保留标签。`keepGroup: 1` 指向标签组，取值在第 2 组。
    //
    // 早先这条规则只有一个 `wxid_` 分支和一个标签分支，`keepGroup: 2` 对前者
    // 取不到第 2 组，输出成 `undefined{{SOCIAL_ID}}`——一段会写进 session 的
    // 坏字符串。拆成两条规则后每条的前缀组都确定存在。
    //
    // Label plus account, label preserved. `keepGroup: 1` is the label group and
    // the value is group 2. The earlier single rule mixed both branches under
    // `keepGroup: 2`, so the `wxid_` branch produced `undefined{{SOCIAL_ID}}`.
    // Splitting them guarantees each rule has its prefix group.
    //
    // 账号上限放宽到 64：平台账号可以很长，`{5,24}` 会把长账号整条漏掉。
    // The account bound is 64: real handles can be long, and `{5,24}` missed them.
    // 右边界：账号后不能紧跟路径分隔符。`QQ 123456789\脱敏测试.txt` 里的
    // 数字是 Windows 目录名（QQ 下载目录），不是社交账号；移除 local-path 后
    // 这类路径片段会被本规则误伤。遇到 `\xxx` 或 `/xxx`（路径）就跳过。
    // Right boundary: skip when the account is immediately followed by a path
    // separator, e.g. `QQ 123456789\file.txt` is a Windows directory, not an ID.
    re: /((?:微信|QQ|qq|wx|wechat|weixin)\s*(?:号|ID|id)?\s*[:：=]?\s*)([A-Za-z0-9_/-]{5,64})(?![\w-])(?![\\/][^\s])/g,
    keepGroup: 1,
    validate: (whole) => {
      const value = /^\s*[\s\S]*?[:：=]?\s*([A-Za-z0-9_/-]+)\s*$/.exec(whole);
      if (value === null) return false;
      return !/^(?:微信|QQ|qq|wx|wechat|weixin)\s*(?:号|ID|id)?$/i.test(value[1]);
    },
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
    // 省/市/区 + 街道/小区/门牌 的组合。占位写法（`XX小区`）同样算住址：
    // 用户贴测试数据时习惯用 X 遮住小区名，但门牌号仍然是真实结构。
    //
    // Province/city/district plus a street or building marker. Placeholder
    // spellings such as `XX小区` count too: people mask the estate name with X
    // but keep the real number structure.
    re: /(?:[\u4e00-\u9fff]{2,8}(?:省|自治区|特别行政区))?[\u4e00-\u9fffXx*]{2,8}(?:市|自治州|地区)[\u4e00-\u9fffXx*]{2,8}(?:区|县|旗)[\u4e00-\u9fffXx*0-9]{0,24}?(?:路|街|道|巷|弄|村|镇|小区|花园|公寓|大厦|号楼|栋|单元|室)[\u4e00-\u9fffXx*0-9]{0,24}/g,
  },
  {
    id: 'home-address-street',
    level: LEVELS.block,
    kind: HIT_KINDS.address,
    to: PLACEHOLDERS.home,
    re: /(?:\d{6}\s*)?[\u4e00-\u9fffXx*]{2,12}(?:路|街|大道|巷)[0-9]{1,5}号[\u4e00-\u9fffXx*0-9]{0,24}(?:室|层|楼|单元|栋|座|号)/g,
  },
  {
    id: 'home-address-district',
    level: LEVELS.block,
    kind: HIT_KINDS.address,
    to: PLACEHOLDERS.home,
    // 区/县/镇 + 路名 + 门牌，但**没有**楼栋号（`朝阳区建国路88号`）。这类
    // 地址同样精确到门牌，却因为缺少省市前缀或楼栋后缀被上面两条规则漏掉。
    // 必须以行政区划词打头，避免把普通「XX路88号」品牌名误判。
    //
    // District/county/town plus a road and house number, with no building suffix
    // (`朝阳区建国路88号`). Such an address is house-precise yet escaped the two
    // rules above; requiring an administrative word keeps brand names out.
    re: /[\u4e00-\u9fff]{2,10}(?:区|县|镇|街道)[\u4e00-\u9fffXx*0-9]{0,12}(?:路|街|大道|巷|道)[0-9]{1,5}号/g,
  },

  // ========== 普通密码：BLOCK（新增） ==========
  {
    id: 'cli-password',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    // 命令行内联密码：`mysql -u root -pSuperSecret123`、`redis-cli -a pass`。
    // 这类写法没有 `password=` 标签，整条凭据规则都看不见，而它恰恰是最常见的
    // 泄露形态（贴一条命令就带出密码）。
    //
    // Inline CLI passwords (`-pSecret`, `--password=...`) carry no label, so the
    // labelled rules miss them; pasting a command is the most common way a
    // password leaks.
    re: /((?:^|\s)(?:-[a-zA-Z]|--[a-z-]*password)\s*)(?!-)[^\s"'`;|&]{6,}/g,
    keepGroup: 1,
    validate: (whole) => {
      // 只认短选项里最常见的密码位：`-p`、`-a`、`-P`、`--password`。
      if (!/(?:^|\s)(?:-p|-a|-P|--[a-z-]*password)/.test(whole)) return false;
      const value = whole.replace(/^\s*(?:-p|-a|-P|--[a-z-]*password)\s*/, '');
      if (value.length < 6) return false;
      // `-p 8080:80`（docker 端口映射）与 `ssh -p 22`（端口）是端口，不是密码：
      // 纯数字或 `数字:数字` 一律按端口放行。
      // `-p 8080:80` (docker) and `ssh -p 22` are ports, not passwords.
      if (/^\d{1,5}(?::\d{1,5})?$/.test(value)) return false;
      return true;
    },
  },
  {
    id: 'kv-credential',
    level: LEVELS.block,
    kind: HIT_KINDS.password,
    to: PLACEHOLDERS.cred,
    re: new RegExp(String.raw`${KV_PREFIX}\s*${KV_VALUE}`, 'gi'),
    keepGroup: 1,
    validate: (whole) => {
      // 取第一个分隔符之后的取值；无分隔符时（`密码Abc@123`）整串即取值。
      let value = whole.replace(/^[\s\S]*?[:=：]\s*["'`]?/, '');
      value = value.replace(ZH_CONNECTORS, '').trim();
      if (value.length === 0) return false;
      return !(DOC_PLACEHOLDER_VALUES.has(value.toLowerCase()) && !/[^A-Za-z0-9]/.test(value));
    },
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
    // 全大写 KEY=VALUE 的形态过宽，会把 `SHA256: <hash>`、`USER_ID=10086`、
    // `MAX_SIZE=1000` 这类非机密也当成凭证。判据：键名是哈希/配置/标识类，
    // 或取值本身是哈希/版本/端口，一律放行。
    //
    // The all-caps KEY=VALUE shape is too broad: `SHA256: <hash>`, `USER_ID=10086`,
    // and `MAX_SIZE=1000` are not credentials. Reject hash/config/identifier keys
    // and hash/version/port-shaped values.
    validate: (whole) => {
      const match = /^\s*(?:export\s+|ENV\s+)?([A-Z][A-Z0-9_]{2,})\s*(?:=>|[:=])\s*["'`]?(.*)$/s.exec(whole.replace(/^\n/, ''));
      if (!match) return true;
      const key = match[1];
      const value = match[2];
      if (/(?:^|_)(?:SHA\d*|MD5|HASH|CHECKSUM|DIGEST|SUM|PORT|TIMEOUT|COUNT|SIZE|LEN|LENGTH|LIMIT|MAX|MIN|DEFAULT|LEVEL|THREADS|WORKERS|INTERVAL|RETRY|DAYS|MS|SECONDS|VERSION|BUILD|REV|REVISION|ID|NO|NUM|NUMBER|CODE|RATE|PERCENT|RATIO)$/.test(key)) return false;
      if (isExcluded(value)) return false;
      return true;
    },
  },

  // ========== 会话凭证：MASK ==========
  {
    id: 'cookie-session',
    level: LEVELS.mask,
    kind: HIT_KINDS.account,
    to: PLACEHOLDERS.cred,
    // 只认真正的会话凭证 / only real session credentials.
    //
    // 早先这条规则把 `Cookie: ` 之后的任何内容整段替换，`Cookie: theme=dark`、
    // `Set-Cookie: lang=zh-CN` 这类纯偏好设置也被遮蔽成 `{{CRED_CODE}}`——过度
    // 遮蔽虽然不影响任务，却让模型读不到正常的 cookie 结构。
    //
    // 现在分三种情况：标签本身是会话名（`sessionid=`、`sid=`）时直接遮蔽；
    // `Cookie:`/`Set-Cookie:` 头只在体内的键名是会话键，或值足够长且不像普通
    // 单词时才遮蔽。
    //
    // The rule used to replace everything after `Cookie: `, so ordinary preference
    // cookies (`theme=dark`, `lang=zh-CN`) were masked too. It now masks when the
    // label is itself a session name, or when the body carries a session-like key,
    // or when the value is long enough to be an opaque token.
    re: /((?:set-cookie|cookie|session[_-]?ids?|session|sid|connect\.sid|jsessionid|phpsessid)\s*[:=]\s*)[^\s;,\n]{8,}/gi,
    keepGroup: 1,
    validate: (whole) => {
      const match = /^\s*(set-cookie|cookie|session[_-]?ids?|session|sid|connect\.sid|jsessionid|phpsessid)\s*[:=]\s*([\s\S]*)$/i.exec(whole);
      if (match === null) return false;
      const label = match[1].toLowerCase();
      const body = match[2].trim();
      if (body.length === 0) return false;
      // 标签自身就是会话名 / the label is a session name itself.
      if (/^(?:session[_-]?ids?|session|sid|connect\.sid|jsessionid|phpsessid)$/.test(label)) return true;
      // 体内含会话键 / the body carries a session-like key. Underscore and hyphen
      // are part of the key, so `auth_token` / `access-token` must both match.
      if (/(?:^|[;,\s])(?:session[_-]?id|sid|jsessionid|phpsessid|token|auth|auth[_-]token|jwt|access[_-]?token|refresh[_-]?token|ticket|csrf|xsrf)\s*=/i.test(body)) return true;
      // 值长且不像普通偏好词 / long enough to be an opaque token.
      return body.replace(/\s/g, '').length >= 24;
    },
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
    // 键名允许下划线/点/连字符分隔：`transaction_id`、`order_no`、`trade-no`
    // 都是常见写法，只认空格会把它们整条漏掉。
    //
    // Keys allow `_`, `.`, and `-` separators (`transaction_id`, `order_no`), which
    // a space-only pattern would miss entirely.
    re: /((?:订单号|订单编号|流水号|交易号|支付单号|order(?:[._\s-]*(?:id|no|number))?|transaction(?:[._\s-]*id)?|trade(?:[._\s-]*no)?|payment[._-]?id)\s*[:=：]?\s*)[A-Za-z0-9_-]{8,}/gi,
    keepGroup: 1,
  },

  // ========== 资金信息：BLOCK ==========
  {
    id: 'account-balance',
    level: LEVELS.block,
    kind: HIT_KINDS.balance,
    to: PLACEHOLDERS.balance,
    // 余额与金额 / account balance and amount.
    //
    // 只遮蔽**带标签的金额**，不碰裸数字：代码里的 `balance = 0`、`amount: 100`
    // （无币种）都是普通变量赋值，整条规则会把它们一起吃掉，破坏代码分析任务。
    //
    // 分两档严格度 / Two strictness tiers:
    //   - 强标签（余额/结余/存款/available balance）：取值可省略币种；
    //   - 弱标签（金额/amount/price）：必须有币种符号或币种代码。
    //
    // 取值后会排除中文量词与运算符号：`余额500元，缴费100元` 必须只吃掉前者，
    // 否则后端金额连同分隔符一起消失，模型读不到结构。
    //
    // Only labelled amounts are masked, never bare numbers: `balance = 0` in code
    // is an ordinary assignment, and claiming it would break code analysis. Strong
    // labels (余额/结余/available balance) tolerate a currency-free value; weak
    // labels (金额/amount/price) require a currency symbol or code. A trailing
    // classifier such as 元 or a separator always terminates the value.
    re: /((?:(?:账户|帐户|可用|当前|我的|应还|还款|支付|到手)?(?:余额|结余|存款|授信额度|金额)|(?:可用|当前)资金|(?:账户|帐户)?(?:balance|available[\s_-]*balance|amount|total[\s_-]*amount|payment[\s_-]*amount)(?![\w]))\s*(?:为|是|[:=：])?\s*["'`]?\s*)((?:(?:人民币|RMB|CNY|USD|EUR|HKD|JPY|GBP)\s*)?[¥￥$€£]?\s*(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?(?![\d.,])\s*(?:元|块|人民币|美元|欧元|港币|日元|英镑|RMB|CNY|USD|EUR|HKD|JPY|GBP|件|个|台|条|笔|次|人|份|张|只)?)/gi,
    keepGroup: 1,
    validate: (whole) => {
      // 取出末段的数字判定，零值与空值不遮蔽。
      const match = /(\d[\d,]*(?:\.\d{1,2})?)/.exec(whole);
      if (match === null) return false;
      const amount = Number(match[1].replace(/,/g, ''));
      if (!Number.isFinite(amount) || amount <= 0) return false;
      // 数量单位后面接数字是库存/计数，不是资金：`库存余额 30 件`。
      // A counter unit means inventory, not money: `库存余额 30 件`.
      const labelOnly = whole.replace(/[\d.,]+/g, '');
      if (/件|个|台|条|笔|次|人|份|张|只|天|年|月|日|小时|分钟|秒/.test(labelOnly)) return false;
      // 弱标签必须带币种信息，避免 `amount: 100` 这类普通变量误伤。
      const strong = /余额|结余|存款|授信额度|资金|balance/i.test(whole);
      const hasCurrency = /[¥￥$€£]|人民币|RMB|CNY|USD|EUR|HKD|JPY|GBP|美元|欧元|港币|日元|英镑|元|块/i.test(whole);
      return strong || hasCurrency;
    },
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
    // 指纹/哈希**必须有标签**才处理：裸的 40/64 位十六进制串更可能是文件
    // 校验和（`SHA256: <hash>`、`md5sum` 输出），不应被判为密钥指纹并替换。
    // 只有带 `fingerprint`/`指纹` 标签时才遮蔽，避免无标签的哈希误报。
    //
    // A fingerprint needs a label. A bare 40/64-hex run is more often a checksum
    // (`SHA256: <hash>`, `md5sum` output) than a key fingerprint, so only the
    // labelled form is masked.
    re: /((?:fingerprint|指纹|key\s*fingerprint)\s*[:=：]?\s*)(?:(?:[0-9A-Fa-f]{2}:){15,31}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{40}(?![0-9A-Fa-f])|[0-9A-Fa-f]{64}(?![0-9A-Fa-f]))/gi,
    keepGroup: 1,
  },

  // ========== 本地路径：已移除 ==========
  // local-path 规则被移除：它会把图片附件的文件名（含绝对路径）替换成
  // {{LOCAL_PATH}}，破坏 DSH 的附件解析，导致图片发送失败。
  // 路径属于低敏信息，且 DSH 附件元数据必须原样保留，故不再脱敏。
  // Removed: it mangled image attachment names containing absolute paths
  // into {{LOCAL_PATH}}, breaking DSH attachment resolution and image sending.
  //
  // 相关规则（高熵串）里的“路径片段排除”逻辑保留，避免把路径误判为密钥。

  // ========== 设备标识：MASK ==========
  {
    id: 'device-id',
    level: LEVELS.mask,
    kind: HIT_KINDS.device,
    to: PLACEHOLDERS.device,
    // UUID、16 位十六进制序列号、15 位 IMEI（全数字）。
    //
    // 边界不能用 `\b` 或 `\w`：中文也属 `\w`，`IMEI861234567890123` 里
    // `I` 与 `8` 之间没有词边界，整条规则会静默失效。
    //
    // 左右边界按分支分别处理：
    //   - UUID / 16 位十六进制：两侧都不许有字母数字，否则会把 git 短提交、
    //     哈希片段、路径片段当成设备号（实测 `ceef6df0a1b2c3d4e5f6` 的后 16
    //     位被误报为设备号）。
    //   - 15 位 IMEI：必须容忍字母标签紧贴（`IMEI861...`、`SN861...`），
    //     所以左侧只排除数字与「字母-」。
    //
    // Per-branch boundaries: the UUID and 16-hex branches forbid any adjacent
    // alphanumeric (a git short hash tail was misread as a device id), while the
    // 15-digit IMEI branch keeps tolerating a glued letter label.
    re: /(?:(?<![0-9A-Za-z])[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|(?<!\d)(?<![A-Za-z]-)\d{15}|(?<![0-9A-Za-z])[0-9A-Fa-f]{16})(?![\dA-Za-z-])/g,
    validate: (value) => {
      if (isExcluded(value) || isPlaceholderNumber(value) || isLikelyHashOrPath(value)) return false;
      // 15 位全数字里，Luhn 通过的 Amex/Diners 是银行卡，必须走 BLOCK 而不是
      // 被当设备号 MASK 掉。设备号校验因此让位于银行卡校验。
      //
      // A Luhn-valid 15-digit run is an Amex/Diners card and must be BLOCK; do not
      // mask it as a device id.
      if (validateBankCard(value)) return false;
      return true;
    },
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
    re: /(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?::[0-9]{1,3}(?:\.[0-9]{1,3}){3})?(?:%(?:25)?[A-Za-z0-9_.-]+)?(?![\w:])/g,
    validate: (value) => value !== '::1' && value !== '::',
    toFor: (value) => (/^(?:f[cd]|fe[89ab])/i.test(value) ? PLACEHOLDERS.lan : PLACEHOLDERS.net),
  },
  {
    id: 'lan-ipv4',
    level: LEVELS.mask,
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.lan,
    // 中文字符也属 \w，`内网IP192.168.1.100` 里 `P192` 之间没有词边界，
    // \b 因此失效。改用显式否定环视：前后都不能是数字或点。
    //
    // Chinese characters count as \w, so `内网IP192.168.1.100` has no word
    // boundary between `P` and `1`, and \b never matches. An explicit
    // negative lookaround replaces it.
    re: /(?<![\d.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3})(?![\d.])/g,
  },
  {
    id: 'net-ipv4',
    level: LEVELS.mask,
    kind: HIT_KINDS.net,
    to: PLACEHOLDERS.net,
    // 同上：显式否定环视取代 \b，否则紧贴中文的 IP 认不出来。
    // Same reason: explicit lookarounds instead of \b.
    re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g,
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
 *
 * 16–19 位、Luhn 通过、排除连续相同数字与递增序列。
 *
 * 注释里说明的「测试卡号 6222000000000000 加入白名单」在这版实现为**结构性
 * 排除**而非名单：该号的后 12 位全为 0，`isTestCard` 直接识别这种形态，
 * 无需穷举样例行。用户实测的 6222021202012345678 不是真实卡号（Luhn 不过），
 * 因此正确放行——这是设计行为，不是漏检。
 *
 * The documented "test card 6222000000000000" is excluded structurally rather
 * than by a literal list: its trailing twelve zeros are recognised by
 * `isTestCard`, so no sample rows are needed. The user's 6222021202012345678
 * fails Luhn and is therefore correctly passed through — that is the design,
 * not a miss.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function validateBankCard(value) {
  const digits = digitsOnly(value);
  if (!/^\d{13,19}$/.test(digits)) return false;
  // Amex 为 15 位（34/37 开头），Diners 为 14 位（30/36/38 开头）。其余 14/15
  // 位数字更可能是 IMEI，交给 `device-id` 按设备号处理，避免把设备串标成卡号。
  //
  // Amex is 15 digits (34/37) and Diners 14 (30/36/38). Other 14/15-digit runs
  // are more likely IMEIs and belong to `device-id`, so the card rule declines
  // them rather than mislabelling a device serial as a card.
  if (digits.length === 15 && !/^3[47]/.test(digits)) return false;
  if (digits.length === 14 && !/^3[068]/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  if (isAscending(digits)) return false;
  if (isTestCard(digits)) return false;
  if (isWhitelistedValue(digits)) return false;
  if (isExcluded(digits)) return false;
  return luhn(digits);
}

/**
 * 样板卡号 / Sample card numbers.
 *
 * 测试卡号的共同特征是大段重复的 0：`6222000000000000`、`4111111111111111`
 * 这类号码出现过一次就不再出现。要求末尾至少 8 个 0 才判定为样板。
 *
 * Sample card numbers repeat zeros in long runs. A trailing run of at least
 * eight zeros marks one.
 */
function isTestCard(digits) {
  return /0{8,}$/.test(digits);
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
 * 设备号候选是否其实是哈希或路径片段 / Whether a device-id candidate is a hash or path fragment.
 *
 * `device-id` 的 16 位十六进制分支会吃掉 git 短提交（`ceef6df0a1b2c3d4e5f6`
 * 的后 16 位）、MAC 地址去掉冒号后的 12 位（不会，12<16，但 16 位 MD5 片段会），
 * 以及 UUID 的无连字符形态。这些都不是设备序列号。
 *
 * 判据：长度恰为 16 且全为十六进制时，若左侧上下文是路径分隔符、或取值本身
 * 由「路径片段 + 十六进制」拼接而成，则不算设备号。调用方无法拿到上下文，
 * 因此这里只做两侧字符的推断：若取值全部是十六进制且长度为 16，只有当它
 * **不像**标准序列号（真实序列号常含非十六进制字符或长度不为 16）时才可疑。
 * 实际误报的根因是左右边界，已在正则里用 `(?<![0-9A-Za-z])` 修掉；此处再
 * 对「纯十六进制 16 位」做一次保守排除：全数字交给 isPlaceholderNumber，
 * 剩下纯 a-f 字母开头的当哈希。
 *
 * Guards the 16-hex branch against git short hashes, de-colonised MACs, and
 * hyphen-less UUID fragments, none of which are device serials.
 */
function isLikelyHashOrPath(value) {
  if (/^[0-9A-Fa-f]{16}$/.test(value)) {
    // 全部由 a-f 组成（没有 0-9）几乎只可能是哈希片段，而非设备号。
    if (/^[A-Fa-f]+$/.test(value)) return true;
    // 形如纯小写十六进制（git 缩写扩展）也当哈希。
    if (/^[0-9a-f]{16}$/.test(value)) return true;
  }
  return false;
}

/**
 * 形如版本号 / Version-shaped value.
 *
 * 护照规则里的 `[A-Z]\d{8,10}` 会吃掉 `v1.2.3` 之类吗？不会（含点）。真正
 * 的误报是 `build20240101` 之类的构建号被 `[A-Z]\d{8}` 命中。这里保守地
 * 排除「字母 + 8~10 位纯数字」里若数字部分是常见日期/版本形态者。
 *
 * Version/build-shaped values: `A20240101` reads as a passport but is a build
 * tag. Reject values whose digit run is an eight-digit date.
 */
function isLikelyVersion(value) {
  const match = /^[A-Za-z](\d{8,10})$/.exec(value);
  if (!match) return false;
  const digits = match[1];
  const year = Number(digits.slice(0, 4));
  const month = Number(digits.slice(4, 6));
  const day = Number(digits.slice(6, 8));
  if (year >= 1990 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31) {
    // 只有数字部分是合法日期、且不是 `E` 开头（护照常见前缀）时才排除。
    return true;
  }
  return false;
}

/**
 * 白名单判定 / Whitelist test.
 *
 * 规格要求白名单优先级最高，命中即跳过所有规则。但「命中」必须精确定义：
 * 只有**整个候选值**等于某个白名单项，或者候选值**本身就是**白名单项的
 * 一种包装形式（如 `your_key` 出现在 `apikey=your_key` 的取值位），才算命中。
 *
 * 早先的实现对短文本做子串包含判断，结果是：一段 98 字的消息只要包含
 * `13800138000`（当时列在样例表里），整段就被放行，真实手机号连同住址、
 * 验证码一起逃过脱敏。这是一个真实缺陷，不是边界情况。
 *
 * The whitelist outranks every rule, but "hit" needs a precise definition: only
 * the whole candidate, or the candidate as a wrapped form of a listed token,
 * counts. The earlier substring test let a 98-character message through because
 * it contained a listed sample number, and a real phone number, address, and
 * OTP escaped together. That was a defect, not an edge case.
 *
 * @param {string} value 候选取值 / candidate value
 * @returns {boolean}
 */
const WHITELIST_CACHE = new WeakMap();
const EMPTY_WHITELIST = Object.freeze([]);

function whitelistSets(additional) {
  const list = Array.isArray(additional) ? additional : EMPTY_WHITELIST;
  let cached = WHITELIST_CACHE.get(list);
  if (cached !== undefined) return cached;
  const tokens = [...new Set([...DEFAULT_WHITELIST, ...list]
    .filter((token) => typeof token === 'string')
    .map((token) => token.toLowerCase()))];
  cached = {
    exact: new Set(tokens),
    bare: new Set(tokens.map((token) => token.replace(/[-_.\s]/g, ''))),
  };
  WHITELIST_CACHE.set(list, cached);
  return cached;
}

export function isWhitelistedValue(value, additional = []) {
  if (typeof value !== 'string' || value.length === 0) return false;
  const lowered = value.toLowerCase();
  const sets = whitelistSets(additional);
  if (sets.exact.has(lowered)) return true;
  return sets.bare.has(lowered.replace(/[-_.\s]/g, ''));
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
  // 版本号（允许两个 `-`/`+` 段，如 `2.14.0-rc.1+build.20261126`）
  if (/^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+){0,2}$/i.test(value)) return true;
  // 十六进制哈希（md5/sha1/sha256/sha512）与 git commit hash
  if (/^[0-9a-f]{7,128}$/i.test(value) && [32, 40, 64, 128].includes(value.length)) return true;
  if (/^[0-9a-f]{7,8}$/i.test(value)) return true;
  // `sha256:<hex>`、`md5:<hex>` 这类带算法前缀的摘要（docker digest、校验和）。
  if (/^(?:sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|md5|blake2b?|crc32):[0-9a-f]{16,}$/i.test(value)) return true;
  // 正则字面量：`/(?<!\d)1[3-9]\d{9}(?!\d)/g` 熵很高，却是代码而非密钥。
  // A regex literal is high-entropy but is code, not a secret.
  if (/^\/(?:[^/\\]|\\.)+\/[gimsuy]*$/.test(value)) return true;
  // 正则/代码片段：高熵兜底可能从 `/` 之后开始截取，导致候选不以 `/` 起头
  // （`(?<!\d)1[3-9]\d{9}(?!\d)/g;`）。含 `(?` 分组或 `\d`/`\w` 转义即判为
  // 代码，避免把正则或转义串当密钥。
  // The entropy fallback can start mid-literal, so the candidate may not begin
  // with `/`. A regex group opener or an escape class marks code, not a secret.
  if (/\//.test(value) && (/\(\?[<!=:]/.test(value) || /\\[dDwWsSbBnrtfv]/.test(value))) return true;
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
 *
 * base64 串必须排除：它的熵天然很高，但「看起来像 base64」不等于「是密钥」。
 * 是否真的敏感由 base64 解码检测回答（`detectBase64` 开关）。
 *
 * Base64 runs are excluded: their entropy is naturally high, and looking like
 * base64 does not make something a secret. Whether the payload is sensitive is
 * answered by the decode check instead.
 */
export function isHighEntropy(value) {
  if (typeof value !== 'string' || value.length < 24) return false;
  if (isExcluded(value)) return false;
  if (isWhitelistedValue(value)) return false;
  if (isBase64Like(value)) return false;
  // URL 天然「熵高」但几乎不含机密：`http://localhost:3000/api/v1/users`、
  // `redis://localhost:6379/0` 都被旧实现整段替换成 `{{SECRET_TOKEN}}`。
  // 含 `://` 的串交给 URL / 私网规则与 db-credential 处理，不进熵兜底。
  //
  // URLs look high-entropy yet rarely hold a secret; the old rule replaced
  // `http://localhost:3000/api/v1/users` wholesale. Anything with `://` belongs
  // to the URL, private-host, and db-credential rules instead.
  if (/[a-z][a-z0-9+.-]*:\/\//i.test(value)) return false;
  // 纯数字/斜杠的长路径（`/a/b/c/...`）是路径而非随机串。
  if (/^\/?~[\\/][\w./~%+-]+$/.test(value)) return false;
  // 绝对路径（含 local-path 曾覆盖的挂载点）：local-path 移除后，这类路径
  // 会落到熵兜底里被误判。以 `/` 开头且只含路径字符的一律不算密钥。
  // Absolute paths used to be caught by local-path; after its removal they
  // must not fall through to the entropy catch-all.
  if (/^\/[A-Za-z0-9._~%+-]+(?:[\\/][A-Za-z0-9._~%+-]*)+$/.test(value)) return false;
  // 堆栈帧与文件路径：`node:internal/modules/cjs/loader:1145:15`、
  // `src/utils/helper.ts:12:5` 熵很高，却是报错栈而非密钥。
  // Stack frames and file paths are high-entropy but are not secrets.
  if (/(?:^|:)[\w.-]+\/[\w./-]+/.test(value)) return false;
  if (/:\d+:\d+\)?$/.test(value)) return false;
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/\d/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  if (classes < 3) return false;
  if (new Set(value).size < 12) return false;
  return shannonEntropy(value) >= 3.0;
}

/**
 * 是否像一个 base64 串 / Whether a value looks like base64.
 *
 * 判据：仅含 base64 字符集、长度是 4 的倍数、且带填充或足够长。
 * 这类串交给解码检测，不参与高熵兜底。
 *
 * Only the base64 alphabet, a multiple-of-four length, and either padding or
 * enough length. Such runs belong to the decode check, not the entropy fallback.
 */
export function isBase64Like(value) {
  if (typeof value !== 'string' || value.length < 24) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  return value.length % 4 === 0 || value.length >= 40;
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
  // ========== 数据库连接串：BLOCK ==========
  //
  // 必须排在网络规则**之前**。连接串里的主机段会被 `lan-ipv4` / `net-ipv4` /
  // `email` 先命中，一旦主机被替换，这条规则就再也看不到 `user:pass@host` 的
  // 完整形态——实测 `postgres://user:pass123@10.0.0.1:5432/db` 输出
  // `postgres://user:pass123@{{LAN_IP}}:5432/db`，**密码段原样保留**。
  // 数据库连接串必须排在网络规则之前，见 `buildRules` 里的顺序说明。
  // Database URLs must precede the network rules; see the ordering note in
  // `buildRules`.
  if (config.maskDbCredentials !== false) {
    rules.push({
      id: 'db-credential',
      level: LEVELS.block,
      kind: HIT_KINDS.password,
      to: PLACEHOLDERS.db,
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|oracle|clickhouse|sqlserver):\/\/[^\s:/@]+:[^\s@/]+@[^\s"'<>]*/gi,
    });
  }
  return rules;
}

/**
 * 高熵兜底规则 / The high-entropy fallback.
 *
 * 它**必须**排在最后：任何更具体的规则（路径、IP、设备号、指纹）都比它更
 * 准确地描述命中，让它先跑会把路径前缀当成随机串吃掉。
 *
 * 这是重构中发现的真实缺陷：它原先位于基础规则表中段，抢在 `local-path`
 * 与 `net-*` 之前匹配，导致 `/storage/emulated/0/DCIM/screenshot.png` 被
 * 归类为「可疑长串」而不是「本地路径」。
 *
 * It **must** run last. Every specific rule describes a hit more precisely, and
 * letting this one run first consumed path prefixes as random strings. That was
 * a real defect found during the refactor: it sat mid-table and claimed
 * `/storage/emulated/0/DCIM/screenshot.png` before `local-path` could.
 *
 * @returns {object}
 */
function highEntropyRule() {
  return {
    id: 'high-entropy',
    level: LEVELS.block,
    kind: HIT_KINDS.entropy,
    to: PLACEHOLDERS.secret,
    // 字符类覆盖 ASCII 可打印符号，但**排除 `=`**（0x3D）：否则
    // `transaction_id=txn_abc123def456` 会连同键名一起被当成一个高熵串整段
    // 替换，交易号规则再无机会按「保留键名、只换取值」处理。这里用两段
    // 区间 `!-<` 与 `>-~` 精确跳过 `=` 一个字符。
    //
    // The class covers printable ASCII but excludes `=` (0x3D); otherwise
    // `transaction_id=txn_...` is consumed whole as one high-entropy run. Two
    // ranges `!-<` and `>-~` skip exactly `=`.
    re: /(?<![\w+/=-])[!-<>-~]{24,}(?![\w+/=-])/g,
    validate: isHighEntropy,
  };
}

/**
 * 组装规则表 / Assemble the rule table.
 *
 * 顺序即识别优先级 / order is the recognition priority:
 *   具体规则（结构、证件、凭证、地址）→ 高熵兜底
 *
 * @param {object} config 归一化配置 / normalized config
 * @param {object[]} [extraRules] 额外规则（住址、病历、姓名+证件）/ extra rules
 */
export function buildRules(config, extraRules = []) {
  const optional = optionalRules(config);
  // 数据库连接串必须排在所有网络规则之前：连接串的主机段会被 `lan-ipv4` /
  // `net-ipv4` / `email` 抢先命中，主机一旦被替换，`user:pass@host` 的完整形态
  // 就再也匹配不到，密码段原样保留。实测：
  // `postgres://user:pass123@10.0.0.1:5432/db` → `postgres://user:pass123@{{LAN_IP}}:5432/db`。
  //
  // A database URL must precede every network rule. Its host is claimed first by
  // `lan-ipv4` / `net-ipv4` / `email`, and once replaced the `user:pass@host` shape
  // is gone, leaving the password in clear text.
  const hoisted = optional.filter((rule) => rule.id === 'db-credential');
  const rest = optional.filter((rule) => rule.id !== 'db-credential');
  // 放在 BASE_RULES **之前**，而不是只提到 optional 内部——网络规则本身就在
  // BASE_RULES 里，排在 optional 前面，只提 optional 内部的顺序不起作用。
  //
  // Placed before BASE_RULES, not merely earlier inside `optional`: the network
  // rules live in BASE_RULES, which already precedes `optional`, so reordering
  // within `optional` alone changed nothing.
  const rules = [...extraRules, ...hoisted, ...BASE_RULES, ...rest];
  if (config.detectHighEntropy !== false) rules.push(highEntropyRule());
  return rules.filter((rule) => !config.disabledRules?.includes(rule.id));
}
