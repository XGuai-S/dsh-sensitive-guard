# 规则清单 / Rule inventory

**自动生成，勿手工编辑。** 由 `node scratch/gen-rules-doc.mjs` 从 `rules.js` 与 `ocr/normalize.js` 枚举得出。

- 版本：**1.7.0**
- 主规则：**47 条**（BLOCK 34 + MASK 13）
- OCR 规则：**7 条**（BLOCK 6 + MASK 1）
- 合计：**54 条**
- 占位符：**26 类**
- 命中类型：**20 种**

---

## 一、主规则（按执行顺序，顺序即优先级）

| # | id | 等级 | 类型 | 占位符 |
|---|---|---|---|---|
| 1 | `name-id-pair` | BLOCK | 身份隐私 | `{{NAME_AND_ID}}` |
| 2 | `cn-address` | BLOCK | 住址 | `{{HOME_ADDR}}` |
| 3 | `street-address` | BLOCK | 住址 | `{{HOME_ADDR}}` |
| 4 | `medical-record` | BLOCK | 身份隐私 | `{{MEDICAL_INFO}}` |
| 5 | `diagnosis-line` | BLOCK | 身份隐私 | `{{MEDICAL_INFO}}` |
| 6 | `medical-id` | BLOCK | 身份隐私 | `{{MEDICAL_INFO}}` |
| 7 | `db-credential` | BLOCK | 密码 | `{{DB_CRED}}` |
| 8 | `pem-private-key` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 9 | `ssh-private-key` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 10 | `key-prefix` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 11 | `jwt` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 12 | `bearer` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 13 | `privileged-password` | BLOCK | 密码 | `{{SECRET_TOKEN}}` |
| 14 | `cn-id-card` | BLOCK | 身份隐私 | `{{ID_CARD}}` |
| 15 | `cn-id-card-spaced` | BLOCK | 身份隐私 | `{{ID_CARD}}` |
| 16 | `bank-card` | BLOCK | 身份隐私 | `{{BANK_CARD}}` |
| 17 | `bank-card-labelled` | BLOCK | 身份隐私 | `{{BANK_CARD}}` |
| 18 | `cvv` | BLOCK | 身份隐私 | `{{BANK_CARD}}` |
| 19 | `passport` | BLOCK | 身份隐私 | `{{PASSPORT_NO}}` |
| 20 | `social-security-card` | BLOCK | 身份隐私 | `{{SOCIAL_CARD}}` |
| 21 | `license-plate` | MASK | 车牌号 | `{{PLATE_NO}}` |
| 22 | `cn-mobile` | BLOCK | 联系方式 | `{{PHONE_NO}}` |
| 23 | `email` | BLOCK | 邮箱 | `{{EMAIL_ADDR}}` |
| 24 | `social-id` | BLOCK | 社交账号 | `{{SOCIAL_ID}}` |
| 25 | `social-id-labelled` | BLOCK | 社交账号 | `{{SOCIAL_ID}}` |
| 26 | `one-time-code` | BLOCK | 验证码 | `{{ONE_TIME_CODE}}` |
| 27 | `home-address` | BLOCK | 住址 | `{{HOME_ADDR}}` |
| 28 | `home-address-street` | BLOCK | 住址 | `{{HOME_ADDR}}` |
| 29 | `home-address-district` | BLOCK | 住址 | `{{HOME_ADDR}}` |
| 30 | `cli-password` | BLOCK | 密码 | `{{CRED_CODE}}` |
| 31 | `kv-credential` | BLOCK | 密码 | `{{CRED_CODE}}` |
| 32 | `service-password` | BLOCK | 密码 | `{{CRED_CODE}}` |
| 33 | `env-credential` | BLOCK | 密码 | `{{CRED_CODE}}` |
| 34 | `cookie-session` | MASK | 账号 | `{{CRED_CODE}}` |
| 35 | `temp-login-link` | MASK | — | `{{CRED_CODE}}` |
| 36 | `url-credential` | MASK | — | `{{CRED_CODE}}` |
| 37 | `trade-no` | MASK | 交易号 | `{{TRADE_NO}}` |
| 38 | `account-balance` | BLOCK | 资金信息 | `{{BALANCE_AMOUNT}}` |
| 39 | `cert-info` | MASK | 证书信息 | `{{CERT_INFO}}` |
| 40 | `key-fingerprint` | MASK | 密钥指纹 | `{{KEY_FINGERPRINT}}` |
| 41 | `local-path` | MASK | 本地路径 | `{{LOCAL_PATH}}` |
| 42 | `device-id` | MASK | 设备信息 | `{{DEVICE_ID}}` |
| 43 | `mac-address` | MASK | MAC地址 | `{{MAC_ADDR}}` |
| 44 | `net-ipv6` | MASK | 网络地址 | `{{NET_IP}}` |
| 45 | `lan-ipv4` | MASK | 网络地址 | `{{LAN_IP}}` |
| 46 | `net-ipv4` | MASK | 网络地址 | `{{NET_IP}}` |
| 47 | `high-entropy` | BLOCK | 可疑长串 | `{{SECRET_TOKEN}}` |

**顺序约束**：

- `name-id-pair` 必须最先，否则证件号先被替换、姓名留在原地。
- `db-credential` 必须排在网络规则之前。连接串的主机段会被 `lan-ipv4` / `net-ipv4` / `email` 抢先命中，主机一旦被替换，`user:pass@host` 就再也匹配不到——实测曾导致密码明文保留。
- `high-entropy` 必须最后，否则会把路径、IP、URL 当作随机串吃掉。

---

## 二、OCR 规则

| # | id | 等级 | 类型 | 占位符 |
|---|---|---|---|---|
| 1 | `ocr-split-secret` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` |
| 2 | `ocr-cn-mobile` | BLOCK | 联系方式 | `{{PHONE_NO}}` |
| 3 | `ocr-cn-id` | BLOCK | 身份隐私 | `{{ID_CARD}}` |
| 4 | `ocr-one-time-code` | BLOCK | 验证码 | `{{ONE_TIME_CODE}}` |
| 5 | `ocr-label-value` | BLOCK | 密码 | `{{CRED_CODE}}` |
| 6 | `ocr-signed-url` | BLOCK | 系统凭证 | `{{CRED_CODE}}` |
| 7 | `ocr-url` | MASK | 网络地址 | `{{PRIVATE_URL}}` |

每条都必须带 `level` 字段——历史上漏写导致整层 OCR 判定恒为 PASS。

---

## 三、占位符（26 类）

| 占位符 | 键名 | 用途 |
|---|---|---|
| `{{SECRET_TOKEN}}` | `secret` | 私钥、API 密钥、Bearer、JWT、高权限密码、高熵串 |
| `{{PRIVACY_ID}}` | `privacy` | 通用身份信息兜底（供自定义规则） |
| `{{ID_CARD}}` | `idCard` | 身份证（含分组书写） |
| `{{PHONE_NO}}` | `phone` | 手机号（含分组、国际区号、前导 0） |
| `{{BANK_CARD}}` | `bankCard` | 银行卡号、CVV |
| `{{PASSPORT_NO}}` | `passport` | 护照号 |
| `{{SOCIAL_CARD}}` | `socialCard` | 社保卡、医保卡 |
| `{{MEDICAL_INFO}}` | `medical` | 门诊号、住院号、诊断、病理 |
| `{{NAME_AND_ID}}` | `nameId` | 姓名 + 证件号组合 |
| `{{CRED_CODE}}` | `cred` | 密码、账号、Cookie、session、URL 凭证 |
| `{{SOCIAL_ID}}` | `social` | 微信、QQ、社交账号 |
| `{{ONE_TIME_CODE}}` | `otp` | 验证码、OTP、2FA |
| `{{NET_IP}}` | `net` | 公网 IP |
| `{{LAN_IP}}` | `lan` | 内网 IP、IPv6 ULA/链路本地 |
| `{{MAC_ADDR}}` | `mac` | MAC 地址 |
| `{{EMAIL_ADDR}}` | `email` | 邮箱 |
| `{{LOCAL_PATH}}` | `path` | 本地绝对路径 |
| `{{DEVICE_ID}}` | `device` | IMEI、Android ID、SN |
| `{{HOME_ADDR}}` | `home` | 物理住址 |
| `{{TRADE_NO}}` | `trade` | 订单号、流水号 |
| `{{CERT_INFO}}` | `cert` | 证书序列号、DN |
| `{{KEY_FINGERPRINT}}` | `fingerprint` | SSH/PGP 指纹 |
| `{{DB_CRED}}` | `db` | 数据库连接串 |
| `{{PRIVATE_URL}}` | `url` | 私有域名、内网地址 |
| `{{PLATE_NO}}` | `plate` | 车牌号 |
| `{{BALANCE_AMOUNT}}` | `balance` | 余额、结余、授信额度、带币种金额 |

**后缀规则**：同会话同值恒定同占位符；类别内第 2–64 个不同值用 `_2`…`_64`；超过则用取值摘要前 4 位（`{{PHONE_NO~53e3}}`）。注册表只存 SHA-256 摘要，不存明文。

---

## 四、命中类型（20 种，用于日志 `hitType`）

`api密钥`、`密码`、`账号`、`验证码`、`可疑长串`、`身份隐私`、`联系方式`、`社交账号`、`住址`、`本地路径`、`设备信息`、`网络地址`、`MAC地址`、`邮箱`、`密钥指纹`、`交易号`、`证书信息`、`绕过尝试`、`车牌号`、`资金信息`

---

## 五、验证方式

`test/rules-coverage.test.mjs` 为 54 条规则各建专属用例，并断言：

- 用例数等于规则数
- 无遗漏规则（逐 id 比对）
- 每条规则都能产出其声明的占位符

判定以**产出占位符**为准，不以规则 id 为准：同类规则（三种住址规则、三种密码规则）谁先命中不影响语义。

---

## 六、已知漏检边界（实测确认，非猜测）

| 形态 | 原因 |
|---|---|
| 无标签且 Luhn 不通过的 13–19 位数字 | 无法与订单号、设备号区分，靠校验位降噪 |
| `邮政as-4124556` 这类「服务名 + 口令」 | 服务名不在密码键词表内；实测 31/32 常见服务名漏检 |
| 全同/递增号码（`11111111111`） | 判为样板数据，故意放行 |
| 纯 `-----BEGIN RSA PRIVATE KEY-----` 头 | 无密钥体，不构成完整 PEM 块 |
| 跨分片边界的敏感值 | 全文探测有兜底，但极端拼接仍可能切断 |
| 流式增量已被下游采集的部分 | `block-end` 改写无法回溯已发出的 `text-delta` |
