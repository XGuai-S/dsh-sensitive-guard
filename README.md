# dsh-sensitive-guard · 敏感内容守卫

[English](README.en.md) | [简体中文](README.zh.md)

---

## 中文

DeepSeek Harness 的宿主插件：在模型请求离开本机、发往中转网关之前，把敏感内容替换为占位符。**不阻断任何请求**，不中断任务，不抛异常。

完整中文文档见 **[README.zh.md](README.zh.md)**。

### 一句话能力

| 能力 | 说明 |
|---|---|
| 文本脱敏 | 密钥、身份隐私、住址、病历、系统凭证、本地路径、设备号、邮箱、IP、私有域名 → 占位符 |
| 图片文字 | Windows 用系统自带 OCR，其他平台用 Python + tesseract；无引擎时仍涂改图片 |
| 不可逆涂改 | 命中整行不透明覆盖 + 整图重编码 + 不写元数据 |
| 二维码 | `jsqr` 解码后按文本规则脱敏 |
| 二进制标记 | 压缩包/二进制只标记，不解析、不破坏 |
| 换机自检 | `node ocr/selfcheck.mjs` 报告本机能力 |

### 快速开始

```bash
npm install                  # 安装 jsqr
node ocr/selfcheck.mjs       # 查看本机具备哪些能力
npm test                     # 46 项回归测试
```

---

## English

A Host plugin for DeepSeek Harness that masks sensitive values before a model
request reaches a provider adapter, reads text and QR payloads out of images,
and never blocks a turn.

Full English documentation: **[README.en.md](README.en.md)**.

### Capabilities at a glance

| Capability | Detail |
|---|---|
| Text masking | secrets, PII, addresses, medical records, credentials, local paths, device ids, emails, IPs, private domains → placeholders |
| Image text | WinRT OCR on Windows, Python + tesseract elsewhere; still redacts when no recognizer exists |
| Irreversible redaction | opaque fill over the matched line + full re-encode + no metadata |
| QR codes | decoded with `jsqr`, then masked by the text rules |
| Binary marking | archives and binaries are reported, never parsed or damaged |
| Portability check | `node ocr/selfcheck.mjs` reports what this machine can do |

### Quick start

```bash
npm install                  # jsqr
node ocr/selfcheck.mjs       # what works here
npm test                     # 46-case regression suite
```

---

## 结构 / Layout

```
index.js              插件主体：规则表、脱敏、三个挂载点
ocr/backend.js        后端选择（winrt / python）
ocr/runner.js         图像操作门面
ocr/normalize.js      OCR 文本归一化与可信度判定
ocr/detect.js         住址、病历、姓名+证件、二进制、二维码
ocr/redact.js         涂改框合并与外扩
ocr/imgops.py         跨平台图像后端（Pillow）
ocr/win-*.ps1         Windows 后端（WinRT）
ocr/selfcheck.mjs     换机自检
test/regression.mjs   46 项回归测试
locale/               插件显示名与描述
docs/                 详情页配图与文档
```

---

## 许可证 / License

MIT，见 [LICENSE](LICENSE)。
