# 脱敏规则总表 / Rule reference

本文件由代码枚举生成，与 `rules.js`、`ocr/normalize.js` 保持一致。
Generated from the code; kept in step with `rules.js` and `ocr/normalize.js`.

**统计**（由代码枚举，v1.7.1）：主规则 **46 条**（BLOCK 34 + MASK 12）+ OCR 规则 **7 条** = **53 条**，占位符 **26 类**（`path` 常量保留兼容，`local-path` 规则已移除），命中类型 20 种。
**Totals** (enumerated from code, v1.7.1): 46 main rules (34 BLOCK + 12 MASK), 7 OCR rules, 26 placeholder classes (`path` constant kept, `local-path` rule removed), 20 hit kinds.

> **本文件的所有数字都由 `scratch/gen-rules-doc.mjs` 从代码导出后写入，不手工维护。** 历史上出现过多次文档与实际不符（规则数、占位符数、中英文数字互相矛盾），因此清单以代码为唯一事实来源。
>
> 主要变更：1.3 修掉 20 处实测缺陷（误报、漏检、坏占位符、整层 OCR 失效）；1.4 拆开混用的占位符（一种语义一个占位符）；1.6 新增余额脱敏、带标签卡号、银行机构名标签。

---

## 一、执行顺序即优先级 / Order is priority

规则按数组顺序依次运行，先命中的先替换，之后的规则看到的是占位符，不会再匹配同一段文本。

Rules run in array order. An earlier hit replaces the text with a placeholder, and
later rules see that placeholder instead of the original — so one value is masked
exactly once.

| 位置 | 规则 | 为什么必须在这个位置 |
|---|---|---|
| 1 | `name-id-pair` | 必须最先，否则证件号先被替换，姓名留在原地 |
| 2–3 | `cn-address` / `street-address` | 住址链要先于门牌号兜底 |
| 4–6 | 病历三规则 | 标签词要先于通用证件识别 |
| 7–18 | 密钥、证件、支付 | 具体规则，越靠前越精确 |
| 19 | `license-plate` | 省份简称固定，形态独特，放在证件簇内即可 |
| 20–30 | 联系、验证码、地址、密码 | 中等宽度，标签驱动 |
| 31–42 | 会话、交易、证书、路径、设备、网络 | 形态较宽，靠后 |
| 43 | `db-credential` | 连接串，需晚于路径与网络 |
| **44** | **`high-entropy`** | **必须最后**，否则会把路径前缀、IP、URL 当作随机串吃掉 |

`high-entropy` 是唯一由 `buildRules()` 在末尾追加的规则，不写在基础表里——
把「必须最后」这件事编码进装配逻辑，比依赖人工维护数组顺序更可靠。

---

## 二、BLOCK 阻断级（31 条，清洗后继续）

命中后**替换为占位符并继续任务**，不中断对话。唯一的「拦截」是绕过攻击指令（见第八节），因为它要求守卫停工，不属于可脱敏内容。

| # | 规则 id | 类型 | 占位符 | 匹配内容 |
|---|---|---|---|---|
| 1 | `name-id-pair` | 身份隐私 | `{{NAME_AND_ID}}` | 姓名（2–4 中文字，非标签词）紧邻 18 位身份证号 |
| 2 | `cn-address` | 住址 | `{{HOME_ADDR}}` | 省/市/区 + 路/街/巷/小区/楼栋 + 门牌（允许字母） |
| 3 | `street-address` | 住址 | `{{HOME_ADDR}}` | 路名 + 门牌 + 室/层/楼/栋 |
| 4 | `medical-record` | 身份隐私 | `{{MEDICAL_INFO}}` | 门诊号/住院号/主诉/既往史 + 取值 |
| 5 | `diagnosis-line` | 身份隐私 | `{{MEDICAL_INFO}}` | 诊断/结论/病理 + 取值 |
| 6 | `medical-id` | 身份隐私 | `{{MEDICAL_INFO}}` | 病历号 + 字母数字（护照规则抢先时的兜底） |
| 7 | `pem-private-key` | api密钥 | `{{SECRET_TOKEN}}` | `BEGIN RSA/EC/DSA/OPENSSH/ENCRYPTED PRIVATE KEY` 整块 |
| 8 | `ssh-private-key` | api密钥 | `{{SECRET_TOKEN}}` | `ssh-rsa`/`ssh-ed25519` + `AAAA` 开头的密钥体 |
| 9 | `key-prefix` | api密钥 | `{{SECRET_TOKEN}}` | 20 种前缀 + ≥8 位密钥体（见下表） |
| 10 | `jwt` | api密钥 | `{{SECRET_TOKEN}}` | `eyJ…eyJ…签名` 三段式 |
| 11 | `bearer` | api密钥 | `{{SECRET_TOKEN}}` | `Bearer xxx`（保留 `Bearer `） |
| 12 | `privileged-password` | 密码 | `{{SECRET_TOKEN}}` | root/ssh/admin/payment/passphrase/管理员 + 密码 + ≥6 位取值 |
| 13 | `cn-id-card` | 身份隐私 | `{{ID_CARD}}` | 18 位身份证，末位可为 X/x |
| 14 | `cn-id-card-spaced` | 身份隐私 | `{{ID_CARD}}` | **带空格分组**的身份证（`1101011990 0307 4513`） |
| 15 | `bank-card` | 身份隐私 | `{{BANK_CARD}}` | 13–19 位 + Luhn 校验（含 Amex 15 位、Diners 14 位，详见下表） |
| 16 | `bank-card-labelled` | 身份隐私 | `{{BANK_CARD}}` | **带标签**（卡号/银行卡/credit card）的 13–19 位，**不做 Luhn**；保留标签 |
| 16 | `cvv` | 身份隐私 | `{{BANK_CARD}}` | CVV/CVC/安全码 + 3–4 位（属卡片信息，与卡号同类） |
| 17 | `passport` | 身份隐私 | `{{PASSPORT_NO}}` | `E12345678` / `G…` / `H…` / 字母+8–10 位（排除构建号形态） |
| 18 | `social-security-card` | 身份隐私 | `{{SOCIAL_CARD}}` | 社保卡/医保卡关键词 + 9–18 位，或 `D` 前缀卡号 |
| 19 | `cn-mobile` | 联系方式 | `{{PHONE_NO}}` | 1 开头 11 位，或空格/连字符分组（`138-0013-8002`），排除全同/递增/白名单 |
| 20 | `email` | 邮箱 | `{{EMAIL_ADDR}}` | 标准邮箱；`user@host`（无点域名）与 `*.internal/.local/.lan` 内网主机名**不**算邮箱 |
| 21 | `social-id` | 社交账号 | `{{SOCIAL_ID}}` | `wxid_` 前缀，或 微信/QQ/wx/wechat + 5–20 位 |
| 22 | `one-time-code` | 验证码 | `{{ONE_TIME_CODE}}` | 验证码/otp/2fa/code/口令 + 4–6 位数字 |
| 23 | `home-address` | 住址 | `{{HOME_ADDR}}` | 省市区 + 路/巷/弄/栋/单元/室 |
| 24 | `home-address-street` | 住址 | `{{HOME_ADDR}}` | 可选邮编 + 路名 + 门牌 + 室/层/楼 |
| 25 | `home-address-district` | 住址 | `{{HOME_ADDR}}` | **区/县/镇 + 路名 + 门牌**（无楼栋后缀，如 `朝阳区建国路88号`） |
| 26 | `cli-password` | 密码 | `{{CRED_CODE}}` | 命令行内联密码：`-pSecret`、`--password=…`（端口 `-p 8080:80` 不算） |
| 27 | `kv-credential` | 密码 | `{{CRED_CODE}}` | 键值对形态（见下表） |
| 28 | `service-password` | 密码 | `{{CRED_CODE}}` | adb/root/ssh/server/db/mysql/postgres/redis/wifi/router + 密码 |
| 29 | `env-credential` | 密码 | `{{CRED_CODE}}` | `export VAR=…` / `ENV VAR …` / `.env` 行（保留变量名；哈希/端口/配置键除外） |
| 30 | `db-credential` | 密码 | `{{DB_CRED}}` | `postgres://user:pass@…` 等 8 种连接串 |
| 31 | `account-balance` | 资金信息 | `{{BALANCE_AMOUNT}}` | 余额/结余/存款/授信额度/balance + 金额（千分位、小数、`¥`/`$`/`USD`）；零值与无币种弱标签放行 |
| 32 | `high-entropy` | 可疑长串 | `{{SECRET_TOKEN}}` | ≥24 位随机串（见下方判定条件） |

### 固定前缀密钥（规则 9 的完整清单）

`github_pat_`、`sk-proj-`、`sk-ant-`、`sk_live_`、`rk_test_`、`whsec_`、`glpat-`、
`xox[baprs]-`、`ssh-ed25519`、`ssh-rsa`、`AKIA`、`ASIA`、`LTAI`、`AKID`、`AIza`、
`ghp_`、`gho_`、`sk-`、`hf_`、`npm_`

**按长度降序排列**，保证 `sk-proj-` 不会被 `sk-` 抢先吃掉前半段。

### 键值对识别（规则 27）

**英文键名**（必须带分隔符，否则 `tokenize something` 会被误判）：
`password`、`passwd`、`pwd`、`secret`、`token`、`key`、`apikey`、`api.key`、
`accesskey`、`access.key`、`access.token`、`auth`、`authorization`、`bearer`、
`sshkey`、`ssh.key`、`private.key`、`passphrase`、`client.secret`、
`storePassword`、`keyPassword`、`pkcs12Password`、`signaturePassword`、`credential`

**中文键名**（分隔符或连接词可选，因为中文习惯直接跟值）：
`账号`、`帐号`、`用户名`、`密码`、`口令`、`数据库密码`、`wifi密码`、`支付密钥`、`密钥`、`pin码`
连接词可以是 `是`、`为`、`的`、`＝`。

**分隔符**：`=`、`:`、`=>`、`：`，以及可选的起始引号 `"` `'` `` ` ``

**文档占位放行**：取值为 `value`/`string`/`token`/`changeme`/`foo` 等纯占位词时不遮蔽，避免 `key=value` 误报。

### 银行卡判定（规则 15）

必须同时满足：

1. 去掉空格与横杠后为 13–19 位纯数字；14/15 位仅接受 Diners(30/36/38) / Amex(34/37)
2. **Luhn 校验通过**
3. 不是全同数字（`1111…`）
4. 不是递增/递减序列（`1234…`）
5. 末尾不是 8 个以上连续的 `0`（样板卡号特征）
6. 不在白名单

**不符合 Luhn 的长数字会被放行**——这是设计取舍，避免把任意 16–19 位数字当卡号。

### 高熵判定（规则 31）

必须同时满足：

1. 长度 ≥ 24
2. 至少包含三类字符（小写、大写、数字、符号）
3. 去重后字符数 ≥ 12
4. 香农熵 ≥ 3.0 比特/字符
5. **不是** base64 形态（由 MASK 规则处理，避免双重命中和误报）
6. 不是排除项（端口、版本号、哈希、UUID、颜色值、寄存器地址、数学算式）
7. **不含 `=`**（`key=value` 形态交给具体键值规则，避免整段吞掉键名）
8. 不是 URL（含 `://`）、不是纯路径、不是堆栈帧（`…/loader:1145:15`）

---

## 三、MASK 脱敏级（13 条，脱敏后写入）

| # | 规则 id | 类型 | 占位符 | 匹配内容 |
|---|---|---|---|---|
| 32 | `license-plate` | 车牌号 | `{{PLATE_NO}}` | 31 个省份简称 + 发牌字母 + 5 位；新能源 `D/F` 前置或末尾；警/学/挂/领/使/港/澳/试/超后缀 |
| 33 | `cookie-session` | 账号 | `{{CRED_CODE}}` | Cookie / set-cookie / session / sessionid / sid / connect.sid / JSESSIONID / PHPSESSID |
| 34 | `temp-login-link` | — | `{{CRED_CODE}}` | 带 `token=` `ticket=` `sign=` `key=` 的完整 URL |
| 35 | `url-credential` | — | `{{CRED_CODE}}` | URL 查询串里的 token/apikey/pwd/password/secret/sessionid |
| 36 | `trade-no` | 交易号 | `{{TRADE_NO}}` | 订单号/流水号/交易号/order/transaction/payment + ≥8 位（键名允许 `_` `.` `-`） |
| 37 | `cert-info` | 证书信息 | `{{CERT_INFO}}` | 证书序列号、serial、subject、DN、证书主题 |
| 38 | `key-fingerprint` | 密钥指纹 | `{{KEY_FINGERPRINT}}` | **必须带标签**（fingerprint/指纹）+ 冒号十六进制、40 位、64 位 |
| 39 | `device-id` | 设备信息 | `{{DEVICE_ID}}` | UUID、16 位十六进制序列号、15 位 IMEI（Luhn 通过的 15 位让给银行卡） |
| 41 | `mac-address` | MAC地址 | `{{MAC_ADDR}}` | `aa:bb:cc:dd:ee:ff` 或 `aa-bb-cc-dd-ee-ff` |
| 42 | `net-ipv6` | 网络地址 | **动态** | 标准 IPv6；ULA（`fc00::/7`）→ `{{LAN_IP}}`，其余 → `{{NET_IP}}` |
| 43 | `lan-ipv4` | 网络地址 | `{{LAN_IP}}` | `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` |
| 44 | `net-ipv4` | 网络地址 | `{{NET_IP}}` | 公网 IPv4（含 `172.32+`），排除回环、广播、示例段 |

---

## 四、OCR 专用规则（7 条，6 BLOCK + 1 MASK）

图片内文字与二维码解析结果走这套规则，比主规则表更宽容——识别引擎会插入空格、拆断 ASCII 串。

> **关键**：这 7 条都带 `level` 字段。历史版本漏写了 `level`，`scanChunk` 读取 `rule.level` 得到 `undefined`，于是整层 OCR 判定恒为 PASS——二维码风险永远不记录、图片涂改永远不触发。1.3 已修复并加回归断言。

| 规则 id | 等级 | 类型 | 占位符 | 说明 |
|---|---|---|---|---|
| `ocr-split-secret` | BLOCK | api密钥 | `{{SECRET_TOKEN}}` | 前缀与密钥体之间可能被空格拆断 |
| `ocr-cn-mobile` | BLOCK | 联系方式 | `{{PHONE_NO}}` | 手机号可能带空格或横杠分隔 |
| `ocr-cn-id` | BLOCK | 身份隐私 | `{{ID_CARD}}` | 18 位身份证 |
| `ocr-one-time-code` | BLOCK | 验证码 | `{{ONE_TIME_CODE}}` | 验证码/otp/code + 4–6 位 |
| `ocr-label-value` | BLOCK | 密码 | `{{CRED_CODE}}` | 密码/口令/密钥/账号 + 必须带分隔符 |
| `ocr-signed-url` | BLOCK | 系统凭证 | `{{CRED_CODE}}` | 查询串里的 token/ticket/code/sign/key |
| `ocr-url` | MASK | 网络地址 | `{{PRIVATE_URL}}` | 完整 URL |

---

## 五、占位符词表（26 类）

**一种语义一个占位符。** 早先手机号、身份证、银行卡、护照、社保卡、病历共用 `{{PRIVACY_ID}}`，只靠 `_2`、`_3` 序号区分。序号是插入顺序编号、不携带语义，读日志的人看不出 `{{PRIVACY_ID_2}}` 是手机号还是卡号；同一段文本里两个不同类型的值谁拿到 `_2` 还取决于规则先后。1.4 起拆分如下。

| 占位符 | 用途 | 等级 |
|---|---|---|
| `{{SECRET_TOKEN}}` | 私钥、API 密钥、Bearer、JWT、高权限密码、高熵串 | BLOCK |
| `{{ID_CARD}}` | 身份证（含分组书写）、OCR 身份证 | BLOCK |
| `{{PHONE_NO}}` | 手机号（含空格/连字符分组）、OCR 手机号 | BLOCK |
| `{{BANK_CARD}}` | 银行卡号、CVV/CVC | BLOCK |
| `{{PASSPORT_NO}}` | 护照号 | BLOCK |
| `{{SOCIAL_CARD}}` | 社保卡、医保卡 | BLOCK |
| `{{MEDICAL_INFO}}` | 门诊号、住院号、诊断、病理、主诉 | BLOCK |
| `{{NAME_AND_ID}}` | 姓名 + 身份证号的组合 | BLOCK |
| `{{PRIVACY_ID}}` | 通用身份信息兜底（保留，供自定义规则） | BLOCK |
| `{{CRED_CODE}}` | 普通密码、账号、Cookie、session、URL 凭证 | BLOCK |
| `{{SOCIAL_ID}}` | 微信、QQ、社交账号 | BLOCK |
| `{{ONE_TIME_CODE}}` | 验证码、OTP、2FA | BLOCK |
| `{{HOME_ADDR}}` | 物理住址 | BLOCK |
| `{{EMAIL_ADDR}}` | 邮箱 | BLOCK |
| `{{DB_CRED}}` | 数据库连接串 | BLOCK |
| `{{BALANCE_AMOUNT}}` | 账户余额、结余、授信额度、带币种的金额 | BLOCK |
| `{{TRADE_NO}}` | 订单号、流水号 | MASK |
| `{{CERT_INFO}}` | 证书序列号、DN | MASK |
| `{{KEY_FINGERPRINT}}` | SSH/PGP 指纹 | MASK |
| `{{LOCAL_PATH}}` | 本地绝对路径 | MASK |
| `{{DEVICE_ID}}` | IMEI、Android ID、SN | MASK |
| `{{MAC_ADDR}}` | MAC 地址 | MASK |
| `{{PLATE_NO}}` | 车牌号 | MASK |
| `{{NET_IP}}` | 公网 IP | MASK |
| `{{LAN_IP}}` | 内网 IP、ULA IPv6 | MASK |
| `{{PRIVATE_URL}}` | 私有域名、内网地址 | MASK |

### 后缀规则 / Suffix policy

同一个值在同一会话内恒定得到同一个占位符；**不同的值必定得到不同的占位符**。

| 情况 | 后缀 | 例 |
|---|---|---|
| 类别内第 1 个不同值 | 无 | `{{PHONE_NO}}` |
| 第 2–64 个不同值 | 递增序号 | `{{PHONE_NO_2}}` … `{{PHONE_NO_64}}` |
| 超过 64 个，或总条目超过 4096 | 取值摘要前 4 位 | `{{PHONE_NO~53e3}}` |

注册表只存 SHA-256 摘要，不存明文。摘要后缀由取值自身派生：不占额外内存、同值恒定、不同值几乎不可能碰撞。

**为什么不用「写满就复用基础占位符」**：1.3 及更早的实现在总条目达 512 后直接返回类别基础占位符，于是**两个不同的真实值拿到同一个占位符**——会话开头的号码与写满之后的另一个号码在日志里无法区分。已实测复现并修复。

---

## 六、白名单降噪 / Whitelist

**优先级最高**，命中即刻跳过全部规则，不标记、不脱敏。

**判定对象**：被替换的那个值（不是整段文本）。长文本不做整段判定，避免子串误伤。

| 类别 | 内容 |
|---|---|
| 回环与广播 | `127.0.0.1`、`::1`、`0.0.0.0`、`255.255.255.255` |
| 示例域名 | `example.com`、`example.org`、`example.net`、`localhost` |
| 示例值 | `test-key`、`demo-key`、`demo-sk`、`test-token`、`example-token`、`mock-secret`、`placeholder`、`your_key`、`your-key`、`yourkey`、`xxx`、`xxxx`、`changeme`、`test/password` |
| 哈希算法名 | `md5`、`sha1`、`sha256`、`sha512` |
| 样板卡号 | `6222000000000000`、`4111111111111111`、`5555555555554444` |

**会话临时白名单**：`sessionWhitelist` 配置项，标记误判内容后当前会话不再脱敏。
**全局永久白名单**：`globalWhitelist` 配置项，并入普通白名单。

---

## 七、排除项 / Exclusions

以下内容**不**判定为敏感：

| 类别 | 说明 |
|---|---|
| 端口 | 1–65535 的纯数字（如 `8080`、`22`） |
| 版本号 | `1.2.3`、`v2.0.0-beta.1`、`v2.14.0-rc.1+build.20261126` |
| 哈希 | MD5(32)、SHA-1(40)、SHA-256(64)、SHA-512(128) 位十六进制 |
| git commit | 7–8 位十六进制 |
| UUID | 标准 8-4-4-4-12 格式 |
| 颜色值 | `#fff`、`#1a2b3c`、`#1a2b3c80` |
| 寄存器地址 | `0x1A2B3C4D` |
| 数学算式 | 含运算符的纯符号数字串 |
| 样板证件 | 全同数字、递增/递减序列 |
| 样板卡号 | 末尾 ≥8 个连续 `0` |

---

## 八、绕过攻击判定 / Bypass

用户指令**要求**守卫停工（跳过脱敏、拆分密钥、编码逃逸、还原占位符、输出原文）时判定为绕过尝试，唯一返回 `reject`、不写 session、不转发模型。

正常开发任务（写编码/加解密/转码函数）**不是**绕过：检测要求「祈使动作 + 目标」同时出现且距离够近。

---

## 九、已知边界 / Known limits

| 边界 | 说明 |
|---|---|
| **Luhn 无效的长数字** | 按设计放行。若希望「形状匹配即脱敏」，可关闭 Luhn 校验 |
| **姓名识别** | 仅识别「姓名紧邻身份证号」的组合。单独姓名不脱敏，因为无法与普通词汇区分 |
| **住址识别** | 要求省/市/区链条或门牌结构。单独城市名、地名不触发 |
| **OCR 置信度** | Windows 中文引擎对每个词返回 `0.000`，改用文本形态判定可靠性 |
| **跨块敏感值** | 响应侧按块脱敏，跨越两个内容块的敏感值无法识别 |
| **原图保留** | 涂改只改变模型收到的内容，`$DSH_HOME/attachments` 下原图仍在 |
| **网关日志** | 中转侧 payload 日志需在网关配置，插件无权控制 |

---

## 十、识别流程 / Pipeline

```
输入文本
   │
   ├─ 1. 白名单判定（整段，仅短文本）
   │     命中 → PASS，不处理
   │
   ├─ 2. 分片（>4096 字符时）
   │     先在完整文本上探测，确认有命中才逐片替换
   │
   ├─ 3. 逐条规则匹配（46 条，按优先级顺序）
   │     ├─ 已含 {{ 的匹配 → 跳过（防二次替换）
   │     ├─ rule.validate 不通过 → 跳过
   │     ├─ 白名单判定取值 → 跳过
   │     ├─ 会话临时白名单 → 跳过
   │     └─ 替换为占位符，记录命中
   │
   ├─ 4. 递归扫描（深度上限 3）
   │     ├─ base64 串解码后重扫（回编码校验）
   │     └─ 嵌套 JSON 解析后重扫字符串叶子
   │
   └─ 5. 二次复检
         MASK 结果再扫一遍，仍检出 BLOCK 则升级为 BLOCK
```

**等级取最高**：同一次扫描中，只要有一条规则是 BLOCK，整体判定就是 BLOCK。

---

## 十一、日志字段 / Log fields

结构化日志固定字段：

| 字段 | 含义 |
|---|---|
| `time` | ISO 8601 时间戳 |
| `source` | 来源：`user_input` / `tool_result` / `model_output` / `request_audit` / `subagent_return` / `rpc_pre_inbox` |
| `level` | `BLOCK` / `MASK` / `PASS` / `ERROR` |
| `hitType` | 命中类型，多类用 `/` 连接 |
| `hitText` | **掩码预览**：前 3 字符 + `***` + 长度，如 `138***(11)` |
| `ruleId` | 首个命中的规则 id |
| `inputHash` | 输入的 SHA-256 前 16 位，用于关联同一段文本的多次扫描 |
| `counts` | 各占位符的命中次数 |

**日志绝不包含原文。** `hitText` 的掩码预览仅够定位类型，不足以复原。
