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

## [1.1.1] - 2026-11-25

真实场景验证发现并修正六个缺陷。对外接口不变。

验证方式：用一条真实短信验证码走完整链路，确认 `agent/inbox/spliced`
写入的是 `{{ONE_TIME_CODE}}` 而非明文；随后对 38 个真实形态的输入逐项检查，
暴露出以下问题。

### 修正

- **密钥前缀正则缺分组**（最严重）。`(?<![\w-])${KEY_PREFIX}body` 里后行断言
  只约束第一个备选，其余前缀从词中任意位置匹配，且密钥体字符类只附着在最后
  一个备选上。后果是 `AKIAIOSFODNN7EXAMPLE` 只替换成
  `{{SECRET_TOKEN}}IOSFODNN7EXAMPLE`，**留下 16 位可读的密钥本体**。
  修法：前缀整体加 `(?:…)` 分组。
- **`sk-proj-` 产生双占位符**。前缀表里 `sk-` 排在 `sk-proj-` 之前，短前缀
  抢先匹配前半段。修法：前缀按长度降序排列。
- **高熵兜底排序错误**。该规则原先位于基础表中段，抢在 `local-path`、
  `net-*` 之前匹配，导致 `/storage/emulated/0/DCIM/screenshot.png` 被归类为
  「可疑长串」。修法：移出基础表，改为 `buildRules` 末尾追加，并新增
  `highEntropyRule()` 单独承载。
- **Linux 绝对路径完全未识别**。`/etc/nginx/nginx.conf` 判为 PASS 原文外泄。
  修法：补 `etc|var|usr|opt|srv|tmp|mnt|media` 前缀；使用具体前缀而非通配
  `/[a-z]+/`，以免吃掉 URL 路径与散文片段。
- **base64 双重误报**。高熵规则把合法 base64 串本身当密钥（其熵确实很高），
  解码检测又只要「解码成功」就判可疑。修法：新增 `isBase64Like()` 供高熵跳过
  base64 形态；解码检测加回编码校验，并要求内层实际命中具体规则。
- **高熵字符类不含符号**。`[A-Za-z0-9+/_-]` 遇 `!` 即截断，只匹配前半段。
  修法：改用 `[!-~]`（全部可打印 ASCII）。

### 测试

- 回归套件扩至 164 项，新增 base64 形态与高熵边界用例。
- 合计 244 项：回归 164、前置拦截 26、架构 54。

## [1.1.0] - 2026-11-25

架构重构。对外行为不变，内部职责重新切分。

### 变更

- **拆分 `index.js`**（773 → 426 行）。抽出四个模块：
  - `session-state.js`：会话级状态（占位符注册表、连续计数、已分析附件、临时白名单）。
  - `accumulator.js`：多次扫描结果的合并与等级提升。
  - `logger.js`：通道选择、格式选择、告警分级。
  - `image-pipeline.js`：图片分析的四道工序。
- 三个挂载点中重复的「按 sessionId 取状态」与「累加结果」样板代码各收敛到一处。
- `files` 清单补全了此前遗漏的源模块，否则发布到 npm 会缺文件。

### 修正

- **内存泄漏**：会话销毁时此前不释放注册表与计数，长跑的 Host 会为每个打开过的会话永久保留状态。现在 `session/disposed` 会调用 `State.forget()`。
- **等级合并**：此前三处各写一份「取较高等级」的比较，其中一处漏掉 MASK 分支。现统一为 `higherLevel()`。

### 测试

- 新增 `test/architecture.test.mjs`，54 项覆盖四个新模块的边界行为（会话隔离、等级合并、日志异常安全、图片替换不可变性）。
- 合计 243 项：回归 163、前置拦截 26、架构 54。

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
