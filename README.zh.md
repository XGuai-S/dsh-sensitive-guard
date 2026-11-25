# dsh-sensitive-guard · 敏感内容守卫

[English](README.en.md) | **简体中文**

DeepSeek Harness 的宿主插件：在模型请求离开本机、发往中转网关之前，把敏感内容替换为占位符。**不阻断任何请求**，不中断任务，不抛异常。

为跨机器使用而设计：没有任何一处写死在特定主机上，并附带自检工具报告当前机器具备哪些能力。

---

## 快速开始

```bash
# 在将运行它的机器上，于插件目录内执行：
npm install                  # 安装 jsqr
node ocr/selfcheck.mjs       # 查看本机具备哪些能力
```

通过 **Plugins → Add plugin** 安装该目录，或使用 `plugin_manager install_bundle`。

---

## 一、核心行为

**唯一结果：脱敏替换。** 每处命中都会被替换为占位符，请求继续走路由、重试、调度。没有拒绝分支；只有日志区分风险等级。

| 命中内容 | 占位符 | 风险等级 |
|---|---|---|
| APIKEY、私钥、`sk-`、`ghp_`、`glpat-`、Bearer、JWT、`storePassword`、pkcs12 | `{{SECRET_TOKEN}}` | 高 |
| 身份证号、手机号、银行卡号、护照号 | `{{PRIVACY_ID}}` | 高 |
| 姓名 + 证件号组合 | `{{PRIVACY_ID}}` | 高 |
| 住址（行政区划链或街道门牌） | `{{PRIVACY_ID}}` | 高 |
| 病历号、诊断行 | `{{PRIVACY_ID}}` | 高 |
| adb/root/wifi/数据库密码、2FA 验证码、Cookie、sessionId、签名登录链接 | `{{CRED_CODE}}` | 高 |
| 数据库连接串 | `{{DB_CRED}}` | 高 |
| 本地绝对路径 | `{{LOCAL_PATH}}` | 普通 |
| IMEI、Android ID、SN 序列号 | `{{DEVICE_ID}}` | 普通 |
| 邮箱地址 | `{{EMAIL_ADDR}}` | 普通 |
| 内网/公网 IP | `{{NET_IP}}` | 普通 |
| 私有域名与仓库地址（可选开启） | `{{PRIVATE_URL}}` | 普通 |

**一条铁律：** 某条规则写入的占位符，不会被后续规则再次匹配。因此每个值只被替换一次，绝不会出现 `_2` 后缀变体。

### 白名单

`test-key`、`demo-sk`、`example-token`、`placeholder`、`mock-secret` 属于文档示例，命中即跳过，不标记、不脱敏。

---

## 二、挂载点

| 事件 | 作用 |
|---|---|
| `agent/pre-step` | 用户输入进入 step 前脱敏；同时分析附加图片 |
| `tools/post-execute` | 工具输出落库前脱敏，避免回放时泄露 |
| `llm/stream` | **仅审计**。循环构建的请求是深冻结的，只能读取记录，不能改写 |

三处监听全部**失败开放**：任何内部异常都返回调用方原决策，守卫永远不会打断一个回合。

---

## 三、图片处理

### 3.1 双后端

两个后端实现同一套五个操作，启动时自动探测并记录实际使用哪一个。

| 后端 | 平台 | 文字识别 | 像素/涂改/缩放 |
|---|---|---|---|
| `winrt` | Windows | 系统自带 `Windows.Media.Ocr` | WinRT 成像 |
| `python` | 任意平台 | `tesseract` 命令行（若已安装） | Pillow |

探测顺序为 `winrt` → `python`。若两者都无法识别文字，守卫**仍然脱敏全部文本、仍然按区域涂改图片**，只丢失「读取画面内文字」这一项。

显式指定（自动探测判断有误时）：

```yaml
config:
  imageBackend: python        # auto | winrt | python | none
  pythonPath: /usr/bin/python3
  tesseractPath: /usr/bin/tesseract
  ocrLanguage: zh-Hans-CN     # winrt 使用
  tesseractLanguage: chi_sim+eng
```

`imageBackend: none` 完全关闭图片分析，文本脱敏不受影响。

### 3.2 识别引擎的坑

Windows 中文识别器对每个词都返回 `0.000` 置信度，无法用阈值判断。因此改用**文本形态**判定：符号占比过高、或有效字符不足两个的行，标记为 `【⚠️OCR识别不可靠】` 并跳过。

它还会在汉字之间插入空格，并可能把 ASCII token 拆断（`sk-abcdefghijklmnopl 234`）。处理方式：

- 归一化只合并**汉字之间**的空格；
- ASCII 空格**不动**——无差别合并会把 `hello world` 变成 `helloworld`；
- 被拆断的 token 由 `ocr-split-secret` 规则**跨空格匹配**解决。

### 3.3 不可逆涂改

命中的整行会被不透明填充覆盖，图片块改指向涂改后的副本。不可逆由三点共同保证：

1. **不透明填充** —— 没有图层、透明度或混合模式，底层像素不可达；
2. **整图重新编码** —— 覆盖区域的原始扫描行在输出文件中完全不存在；
3. **保存时不写元数据** —— EXIF/GPS/机型不会回来。

实测：覆盖后用同一引擎重新识别，输出为 **0 行文字**。

> **做不到的事：** 附件存储是内容寻址且不可变的，原始文件仍留在 `$DSH_HOME/attachments`。涂改改变的是**模型收到的内容**，不是**宿主保留的内容**。能访问本机文件系统的人仍可打开原图。

---

## 四、二维码

二维码载荷在进程内用 `jsqr` 解码，并按文本规则脱敏。命中记为 `【⚠️二维码命中】`。

二维码本身**不涂改**：覆盖会毁掉整个码，且二维码是单一区块而非行结构。解码失败记为 `【⚠️二维码解析异常】`，图片放行。

`jsqr` 是可选依赖。没有它时跳过二维码检测，其余能力全部正常。

---

## 五、二进制与压缩包

zip、rar、7z、gzip、pdf，以及前导窗口含 NUL 字节的文件，一律视为不透明内容。

理由：在压缩包或 base64 块里「脱敏」一个偶然的字节序列，只会破坏文件而不会隐藏任何东西。因此记为 `【⚠️放行-二进制内容】`，字节原样保留。

---

## 六、旁路检测

没有 sessionId 的模型请求，不是由 Agent 循环为某个已知会话构建的——这是一条绕过正常路径的直连调用。它**仍会被审计**，旁路行为记为 `【⚠️旁路风险】`。

## 七、子代理继承

插件全局挂载，子代理的请求经过**同一套** `agent/pre-step`、`tools/post-execute`、`llm/stream` 监听，无需任何按代理的配置。没有独立的子代理开关，因为不存在需要单独覆盖的独立路径。

---

## 八、URL 脱敏分级

把公网域名全部替换会让模型读不懂上下文，因此 `maskUrls` 有三档：

| 取值 | 效果 |
|---|---|
| `false`（默认） | 不处理 |
| `'internal'` | **只处理** `internal`、`local`、`lan`、`corp`、`intra`、`private`、`svc`、`home` 后缀的主机 |
| `'all'` | 所有域名，含公网 |

`privateUrlSuffixes` 可替换内置内网后缀列表。**推荐用 `'internal'`**：内网地址被脱敏，`github.com` 保持可读。

---

## 九、配置项

| 字段 | 默认值 | 含义 |
|---|---|---|
| `enabled` | `true` | 总开关 |
| `maskUserMessages` | `true` | 在 `agent/pre-step` 脱敏用户文本 |
| `maskToolResults` | `true` | 在 `tools/post-execute` 脱敏工具输出 |
| `maskUrls` | `false` | `false`、`internal`、`all` |
| `privateUrlSuffixes` | 内置 | 内网主机后缀 |
| `maskDbCredentials` | `true` | 脱敏数据库连接串 |
| `auditRequests` | `true` | 派发时报告残余命中 |
| `highRiskAlertAfter` | `6` | 连续命中高风险多少次后告警 |
| `maxImagesPerTurn` | `3` | 单轮图片超过此数记告警 |
| `ocr` | `true` | 是否分析图片 |
| `imageBackend` | `auto` | `auto`、`winrt`、`python`、`none` |
| `pythonPath` | PATH 查找 | Python 解释器 |
| `tesseractPath` | PATH 查找 | Tesseract 可执行文件 |
| `ocrLanguage` | `zh-Hans-CN` | WinRT 语言标签 |
| `tesseractLanguage` | `chi_sim+eng` | Tesseract 语言包 |
| `ocrTimeoutMs` | `20000` | 单张图片超时 |
| `ocrMaxImagesPerTurn` | `3` | 每步分析图片数上限 |
| `redactImages` | `true` | 用不透明填充覆盖敏感文字 |
| `redactColor` | `#000000` | 填充色，`#RRGGBB` |
| `detectAddresses` | `true` | 脱敏住址形态的文本 |
| `detectMedical` | `true` | 脱敏病历标记 |
| `detectQr` | `true` | 解码并脱敏二维码载荷 |
| `markBinary` | `true` | 标记压缩包与二进制文件，从不解析内部 |
| `detectBypass` | `true` | 报告无 sessionId 的请求 |
| `compressImages` | `true` | 上传前降分辨率 |
| `compressMaxDimension` | `2048` | 长边像素上限 |
| `disabledRules` | `[]` | 要跳过的规则 id |
| `whitelist` | 内置示例值 | 永不脱敏的值 |
| `logMasks` | `true` | 记录标记但不含原值 |

---

## 十、换机使用

复制整个插件目录，然后：

1. `npm install` —— 安装 `jsqr`。跳过则二维码检测不可用；
2. `node ocr/selfcheck.mjs` —— 打印本机能力清单；
3. 若在非 Windows 平台需要图片文字识别，安装 Pillow（`pip install pillow`）和对应语言包的 tesseract。

自检逐项输出 `OK` / `WARN` / `MISS`，只有真实故障才返回非零退出码，可直接用于脚本。`--json` 输出结构化结果。

---

## 十一、保证与边界

- 替换是**单次正向**的。原值不保存、不还原、不记录。
- 会话占位符注册表只保留每个值的 **SHA-256 摘要**，绝不保留原值。因此同一会话内同一密钥始终得到同一占位符，而明文不会被留存。
- 插件只能约束**本 Host 构建的请求**。它无法关闭第三方中转网关的日志——那是网关侧的配置。
- 规则基于模式匹配，覆盖上文列出的格式，不覆盖所有可能的写法。请按自己的语料补充规则或使用 `disabledRules`。
- 住址与病历检测**刻意收窄**：只对行政区划链和临床标记触发，宁可牺牲召回率，也不误伤普通叙述。

---

## 十二、许可证

MIT，见 [LICENSE](LICENSE)。
