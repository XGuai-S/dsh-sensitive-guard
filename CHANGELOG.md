# 变更记录 / Changelog

本文件记录本插件的所有重要变更。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## 版本策略 / Versioning policy

- **主版本（major）**：改变已有行为的语义。例如「命中阻断级内容时拒绝整条消息」改为「清洗后继续」，使用者需要调整预期。
- **次版本（minor）**：新增能力，旧用法不受影响。例如新增一类占位符、新增一个挂载点。
- **补丁（patch）**：修正缺陷、调整正则、补文档，不改变对外行为。

早期版本曾把每次改动都升一位主版本，把版本号当成工作日志，导致使用者无法判断升级风险。从 1.0.0 起按上述规则执行。

---

## [Unreleased]

## [1.0.0] - 2026-11-25

这是第一个按语义化版本管理的版本。功能上等同于此前标记为 7.0.0 的状态，
版本号收敛是因为此前的编号不反映兼容性。

### 核心行为

- 三级分类：`BLOCK` 阻断级、`MASK` 脱敏级、`PASS` 放行级。
- 默认**清洗后继续**：命中敏感内容时替换为占位符，任务不中断。
- 仅绕过攻击指令被拒绝，不转发给模型。
- 双向扫描：请求侧与模型返回侧都脱敏。

### 挂载点

- `typertGateway.dispatchRpc` — 在 RPC payload 进入 inbox 之前清洗，明文不落盘。
- `agent/pre-step` — 用户输入进入 step 前脱敏，并分析附带图片。
- `tools/post-execute` — 工具与子代理输出入库前二次分级。
- `llm/stream` — 请求侧审计 + 响应侧流式扫描。
- `subagent/end` — 子代理回传主会话前再扫一轮。

### 占位符

`{{SECRET_TOKEN}}`、`{{PRIVACY_ID}}`、`{{CRED_CODE}}`、`{{SOCIAL_ID}}`、
`{{ONE_TIME_CODE}}`、`{{NET_IP}}`、`{{LAN_IP}}`、`{{MAC_ADDR}}`、
`{{EMAIL_ADDR}}`、`{{LOCAL_PATH}}`、`{{DEVICE_ID}}`、`{{HOME_ADDR}}`、
`{{TRADE_NO}}`、`{{CERT_INFO}}`、`{{KEY_FINGERPRINT}}`、`{{DB_CRED}}`、
`{{PRIVATE_URL}}`。

### 识别能力

- 私钥：PEM 五种格式、SSH 私钥行。
- 高权限密钥：`sk-`、`sk-proj-`、`sk-ant-`、`ghp_`、`github_pat_`、`glpat-`、
  `AKIA`、`AIza`、`hf_`、`xox[baprs]-` 等前缀，以及标准 JWT。
- 身份与支付：身份证、银行卡（Luhn 校验）、护照、CVV。
- 联系类：手机号、邮箱、微信号、QQ 号。
- 一次性凭证：短信验证码、2FA、TOTP。
- 位置信息：行政区划链、街道门牌组合。
- 网络：IPv4、IPv6（含 ULA 内网）、MAC、内网网段、私有域名。
- 设备与会话：IMEI、Android ID、SN、Cookie、sessionId。
- 交易与证书：订单流水号、证书序列号与 DN、SSH/PGP 指纹。
- 本地路径：Windows、Linux、Android 绝对路径。
- 高熵兜底：长度 ≥ 24、至少三类字符、去重 ≥ 12、香农熵 ≥ 3.0。

### 降噪

排除端口、版本号、MD5/SHA 系列哈希、UUID、颜色值、数学算式、寄存器地址、
git commit hash，以及内置白名单中的示例值与样板证件号。

### 结构化文本

JSON、YAML、properties、.env、toml、gradle 只替换 value，保留 key；
嵌套 JSON 与一层 base64 递归扫描，深度上限 3 层；
超大文本按边界分片，单片上限 4096 字符。

### 图片

本地 OCR（Windows WinRT 或 Python + tesseract）识别画面文字，结果走同一套规则；
命中行用不透明填充涂改并重新编码，不可逆；
二维码本地解码后扫描；二进制与压缩包不解析内部，标记放行。

### 安全设计

- 单次正向替换，明文不落盘、不还原、不进日志。
- 会话内同一值恒定同一占位符，注册表只存 SHA-256 摘要。
- 占位符一经写入不再被后续规则匹配。
- 日志只含掩码预览（前 3 字符 + 长度），不含原文。
- 任何内部异常都放行原决策，守卫绝不弄坏一个回合。

### 工具

- `npm test` — 回归测试。
- `node ocr/selfcheck.mjs` — 换机能力自检。
- `node scripts/scrub-session.mjs --all --dry-run` — 扫描历史日志中的明文。
