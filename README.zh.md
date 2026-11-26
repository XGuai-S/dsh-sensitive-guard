# 敏感内容守卫

> 安装命令（带一键复制按钮）：打开 [`market/install.html`](market/install.html)，或在 DSH 插件市场添加来源 `https://raw.githubusercontent.com/XGuai-S/dsh-sensitive-guard/main/market/index.json`。

DeepSeek Harness 的请求前置守卫：在内容发往中转网关之前完成识别、脱敏与拦截判定。
执行优先级高于路由、重试、模型调度，全程无交互、不询问。

## 两种模式

| 模式 | 行为 |
|---|---|
| `mask`（默认） | 脱敏放行：命中即替换为占位符，任务继续，仅日志区分风险等级 |
| `block` | 严格阻断：命中高风险时抛出 `CONTENT_REFUSED`，不发起请求、不产生请求体 |

切换方式：

```yaml
config:
  mode: block
  blockOnRisk: high    # high | normal
```

## 双向扫描

| 方向 | 挂载点 | 行为 |
|---|---|---|
| 请求侧 | `agent/pre-step` | 用户输入进入 step 前脱敏，并分析附带图片 |
| 请求侧 | `tools/post-execute` | 工具输出落库前脱敏 |
| 请求侧 | `llm/stream` | 审计即将发出的请求，检出残余命中并告警 |
| 响应侧 | `llm/stream` | 模型返回的文本块在闭合时脱敏 |

响应侧为什么可行：DSH 的 `BlockAssembler` 在收到 `block-end` 时会用该块覆盖此前累积的
`text-delta`。因此把整块文本脱敏后再发一个 `block-end`，下游拿到的就是脱敏后的内容，
不必改动已经发出的增量。

## 脱敏映射

| 命中内容 | 占位符 |
|---|---|
| 明文密钥、私钥、Bearer、JWT、高权限密码、高熵可疑长串 | `{{SECRET_TOKEN}}` |
| 身份证（含分组书写） | `{{ID_CARD}}` |
| 手机号（含空格/连字符分组） | `{{PHONE_NO}}` |
| 银行卡号、CVV/CVC | `{{BANK_CARD}}` |
| 护照号 | `{{PASSPORT_NO}}` |
| 社保卡、医保卡 | `{{SOCIAL_CARD}}` |
| 门诊号、住院号、诊断、病理 | `{{MEDICAL_INFO}}` |
| 姓名 + 身份证号的组合 | `{{NAME_AND_ID}}` |
| 住址 | `{{HOME_ADDR}}` |
| 账号密码、数据库密码、wifi 密码、Cookie、sessionId、临时登录链接 | `{{CRED_CODE}}` |
| 验证码（关键词 + 4–6 位数字） | `{{ONE_TIME_CODE}}` |
| 微信、QQ、社交账号 | `{{SOCIAL_ID}}` |
| 订单号、流水号 | `{{TRADE_NO}}` |
| 证书序列号、DN、密钥指纹 | `{{CERT_INFO}}` / `{{KEY_FINGERPRINT}}` |
| IMEI、Android ID、SN | `{{DEVICE_ID}}` |
| 邮箱 | `{{EMAIL_ADDR}}` |
| 车牌号 | `{{PLATE_NO}}` |
| 内网 IP | `{{LAN_IP}}` |
| 公网 IP | `{{NET_IP}}` |
| 私有域名、内网地址 | `{{PRIVATE_URL}}` |
| 数据库连接账号段 | `{{DB_CRED}}` |
| 账户余额、结余、授信额度、带币种的金额 | `{{BALANCE_AMOUNT}}` |

**一种语义一个占位符**：手机号与身份证不再共用同一个占位符家族，日志里一眼能分清。
同一会话内同值恒定同一占位符；不同值必定不同——类别内第 2–64 个用 `_2`…`_64` 序号，
更多时用取值摘要后缀（`{{PHONE_NO~53e3}}`），不会塌缩成同一个。

## 识别细则

### 键值对凭证

识别 `password`、`pwd`、`secret`、`token`、`key`、`apikey`、`access_key`、`bearer`、
`账号`、`密码`、`数据库密码`、`wifi密码` 等关键字，后跟 `=`、`:`、`：` 或引号时，
**只替换取值，保留键名与分隔符**，因此 JSON、YAML、properties、gradle 结构不被破坏。

```json
{"password":"mySecret123"}  →  {"password":"{{CRED_CODE}}"}
```

```properties
storePassword=abcdef123456  →  storePassword={{CRED_CODE}}
```

### 固定前缀密钥

`sk-`、`sk-proj-`、`sk-ant-`、`ghp_`、`github_pat_`、`glpat-`、`AKIA`、`AIza`、`hf_`、
`eyJ` 开头的字符串判定为 API 密钥。

### 高熵兜底

无标记、无前缀的连续随机字符，长度 ≥ 24 且满足以下全部条件时判定为可疑凭证：

- 至少包含三类字符（小写、大写、数字、符号）
- 去重后字符数 ≥ 12
- 香农熵 ≥ 3.0 比特/字符
- 不是 URL（含 `://`）、不是纯路径、不是堆栈帧、不是正则字面量
- 不含 `=`（`key=value` 交给键值对规则，避免整段吞掉键名）

命中后标记 `【⚠️高熵可疑密钥】` 并脱敏。

### 排除规则

以下内容**不**判定为凭证：

- 端口号（1–65535）
- 版本号（`1.2.3`、`v2.0.0-beta.1`、`v2.14.0-rc.1+build.20261126`）
- MD5 / SHA-1 / SHA-256 / SHA-512 哈希串，以及 `sha256:<hex>` 摘要
- UUID、颜色值、寄存器地址、git commit hash、数学算式

## 规则规模

主规则 **46 条**（BLOCK 34 + MASK 12）+ OCR 规则 **7 条** = **53 条**，占位符 **26 类**（`path` 常量保留兼容，脱敏规则已移除）。
完整清单见 [docs/RULES-INVENTORY.md](docs/RULES-INVENTORY.md)
（逐条判定说明见 [docs/RULES.md](docs/RULES.md)）。

## 白名单

内置：`test-key`、`demo-sk`、`example-token`、`placeholder`、`mock-secret`、`md5`、`sha256`。

命中白名单的字符串不识别、不标记、不脱敏。判定对象是**被替换的值**，不是整段匹配，
因此 `apikey=test-key` 会完整保留。

### 会话临时白名单

标记误判内容后，当前会话不再重复脱敏：

```yaml
config:
  sessionWhitelist:
    - myFalsePositive
```

## 图片处理

1. 上传前清除 EXIF（GPS、拍摄时间、设备型号、序列号）——由 `dsh-attachment-local`
   在入库时完成。
2. 本地 OCR 识别画面文字，结果走同一套脱敏规则。
3. 二维码解码，解析结果同样脱敏。
4. OCR 失败、乱码、置信度低：标记 `【⚠️OCR识别不可靠】`，抹除元数据后放行。
5. 图片统一压缩分辨率，不上传原图。

### 不可逆涂改

命中规则的行用不透明纯色填充，然后整图重新编码。三个条件共同保证不可逆：

1. **不透明填充**——没有图层、透明度或混合模式，底层像素不可达。
2. **整图重新编码**——覆盖区域的原始扫描行在输出文件里完全不存在。
3. **保存时不写元数据**——EXIF/GPS/机型不会回来。

实测：覆盖后用同一引擎重新 OCR，识别出 0 行文字。

**限制**：`$DSH_HOME/attachments` 下的原始文件仍在。附件存储是内容寻址且不可变的，
脱敏改变的是模型收到的内容，不是宿主保留的内容。

### 双后端

| 后端 | 平台 | 文字识别 | 像素/涂改/压缩 |
|---|---|---|---|
| `winrt` | Windows | 系统自带 `Windows.Media.Ocr` | WinRT 成像 |
| `python` | 任意 | `tesseract`（若已安装） | Pillow |

探测顺序 `winrt → python`。都不可用时仍能脱敏全部文本，仍能按区域涂改图片，
只失去「读出画面里的文字」这一步。

```yaml
config:
  imageBackend: python        # auto | winrt | python | none
  pythonPath: /usr/bin/python3
  tesseractPath: /usr/bin/tesseract
```

### 识别引擎的坑

Windows 中文引擎对每个词都返回 `0.000` 置信度，无法用阈值判断，因此改为按文本形态判定：
符号占比过高或有效字符不足两个时标记不可信并跳过。它还会在中文之间插空格、拆断 ASCII 串；
中文空格会合并，ASCII 空格保留（否则 `hello world` 会变成 `helloworld`），
被拆断的密钥由跨空格规则匹配。

## 旁路与子代理

- **旁路检测**：没有会话归属的请求不是 Agent 循环构建的，标记 `【⚠️旁路风险】`，仍然审计。
- **子代理继承**：插件全局挂载，子代理请求走同一套挂载点，无需额外配置。
- **独立计数**：告警按会话独立累计，子代理不与主会话共享命中统计。

## 限流与兜底

| 项目 | 行为 |
|---|---|
| 单轮图片 | 最多 3 张做 OCR，超出部分标记 `【⚠️放行-OCR超限】` |
| 正则 / OCR / 二维码异常 | 标记风险，不中断，继续流转 |
| 连续 6 次高风险 | 输出 `【⚠️告警】` |
| 二进制 / 压缩包 | 标记 `【⚠️放行-二进制内容】`，不解析内部，放行 |

任何内部异常都返回原决策，守卫本身绝不弄坏一个回合。

## 日志

| 日志 | 含义 |
|---|---|
| `【⚠️已脱敏-高风险】` | 命中高风险规则 |
| `【⚠️已脱敏-普通】` | 命中普通规则 |
| `【✅无敏感】` | 本轮无命中 |
| `【⚠️已脱敏-高风险】[对话明文] 命中=密码` | 标注挂载点与命中类型 |

日志只输出占位符与计数，**不输出原文**。

## 占位符稳定性

同一个值在同一会话内恒定得到同一个占位符，防止上下文错乱。注册表只存 SHA-256 摘要，
不存明文。占位符一经写入，后续规则不再匹配，因此同一个值只替换一次。

## 配置项

| 字段 | 默认 | 含义 |
|---|---|---|
| `enabled` | `true` | 总开关 |
| `mode` | `mask` | `mask` 脱敏放行 / `block` 严格阻断 |
| `blockOnRisk` | `high` | 严格模式的触发等级 |
| `maskUserMessages` | `true` | 脱敏用户输入 |
| `maskToolResults` | `true` | 脱敏工具输出 |
| `maskResponses` | `true` | 脱敏模型返回 |
| `auditRequests` | `true` | 审计即将发出的请求 |
| `detectHighEntropy` | `true` | 高熵兜底识别 |
| `detectAddresses` | `true` | 住址识别 |
| `detectMedical` | `true` | 病历识别 |
| `detectQr` | `true` | 二维码解码 |
| `detectBypass` | `true` | 旁路检测 |
| `markBinary` | `true` | 二进制标记 |
| `maskDbCredentials` | `true` | 数据库连接串 |
| `maskUrls` | `false` | `false` / `internal` / `all` |
| `privateUrlSuffixes` | 内置 | 内网后缀列表 |
| `whitelist` | 内置 | 白名单 |
| `sessionWhitelist` | `[]` | 会话临时白名单 |
| `logMasks` | `true` | 输出脱敏日志 |
| `highRiskAlertAfter` | `6` | 连续高危告警阈值 |
| `disabledRules` | `[]` | 禁用的规则 id |
| `maxImagesPerTurn` | `3` | 图片数量告警阈值 |
| `ocr` | `true` | 图片分析总开关 |
| `imageBackend` | `auto` | `auto` / `winrt` / `python` / `none` |
| `pythonPath` | PATH 查找 | Python 解释器 |
| `tesseractPath` | PATH 查找 | Tesseract 可执行文件 |
| `ocrLanguage` | `zh-Hans-CN` | WinRT 语言标签 |
| `tesseractLanguage` | `chi_sim+eng` | Tesseract 语言包 |
| `ocrTimeoutMs` | `20000` | 单图超时 |
| `ocrMaxImagesPerTurn` | `3` | 单轮 OCR 上限 |
| `redactImages` | `true` | 不可逆涂改 |
| `redactColor` | `#000000` | 涂改颜色 |
| `compressImages` | `true` | 压缩分辨率 |
| `compressMaxDimension` | `2048` | 长边上限 |

## URL 脱敏分级

| 值 | 效果 |
|---|---|
| `false`（默认） | 不处理 |
| `internal` | 只脱 `.internal` `.local` `.lan` `.corp` `.intra` `.private` `.svc` `.home` |
| `all` | 全部域名，含公网 |

推荐 `internal`：内网地址被脱敏，`github.com` 保持可读。

## 换机使用

1. 复制整个目录。
2. `npm install` 安装 `jsqr`（跳过则二维码检测失效，其余功能正常）。
3. `node ocr/selfcheck.mjs` 查看本机能力。
4. 需要图像文字识别时：非 Windows 安装 Pillow（`pip install pillow`）与 tesseract 及语言包。

自检按能力输出 `OK` / `WARN` / `MISS`，只有真实故障才返回非零，可进脚本。
`--json` 输出结构化结果。

## 校验约束

- 只替换敏感值，保留代码结构、注释、变量名，不破坏插件安装与代码审计流水线。
- 仅内存瞬时替换，不反向还原、不持久保存原始明文；日志只存摘要。
- 脱敏完成后正常进入路由、重试、中转调度。

## 做不到的事

- **中转侧 payload 日志**：需在网关配置中关闭，插件无权控制。
- **磁盘原图抹除**：附件存储内容寻址且不可变。
- **流式增量已显示原文**：响应侧脱敏在块闭合时生效，进入日志与后续请求的内容是脱敏后的，
  但已经渲染到界面的增量不会回溯。
- **正则的固有局限**：规则覆盖列出的格式，不覆盖所有可能的写法。

## 许可证

MIT
