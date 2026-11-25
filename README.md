# 敏感内容守卫 / Sensitive content guard

DeepSeek Harness 的请求前置守卫：在内容发往中转网关之前完成识别、脱敏与拦截判定。
A pre-gateway guard for DeepSeek Harness that recognizes, masks, and optionally blocks
sensitive content before a request leaves the machine.

**中文文档** → [README.zh.md](README.zh.md)
**English documentation** → [README.en.md](README.en.md)

---

## 一句话说明 / In one line

默认**脱敏放行**：命中即替换为占位符，任务不中断；可切换**严格阻断**模式。
Default is **mask-and-pass**: a hit becomes a placeholder and the task continues.
A **strict block** mode is available.

## 快速开始 / Quick start

```bash
npm install                  # 安装 jsqr / install jsqr
node ocr/selfcheck.mjs       # 本机能力自检 / what works here
npm test                     # 104 项回归 / regression suite
```

在 DSH 的 **插件 → 添加插件** 中安装本目录，或用 `plugin_manager install_bundle`。
Install this directory through **Plugins → Add plugin**, or with
`plugin_manager install_bundle`.

## 能力概览 / Capabilities

| 能力 Capability | 状态 Status |
|---|---|
| 明文密钥、身份隐私、系统凭证、验证码 | ✅ |
| 高熵可疑长串（排除端口/版本/哈希） | ✅ |
| JSON / YAML / properties / gradle 结构化替换 | ✅ |
| 双向扫描（请求侧 + 响应侧） | ✅ |
| 严格阻断模式 | ✅ |
| 白名单 + 会话临时白名单 | ✅ |
| 图片 OCR、二维码、不可逆涂改、压缩 | ✅ |
| 二进制与压缩包标记放行 | ✅ |
| 旁路检测、子代理继承、独立计数 | ✅ |
| Windows WinRT 后端 / 跨平台 Python 后端 | ✅ |

## 已知边界 / Known limits

- 图片内的文字无法就地改写：命中行用不透明填充覆盖后重新编码，模型看不到被覆盖内容，
  但 `$DSH_HOME/attachments` 下的原始文件仍在（内容寻址存储不可变）。
- 中转侧 payload 日志需在网关配置中关闭，插件无权控制。
- 响应侧脱敏在块闭合时生效；流式增量可能已显示过原文，进入会话日志与后续请求的内容是脱敏后的。

- Text inside a raster cannot be edited in place: hit lines are covered by an opaque
  fill and re-encoded. The original file remains in the content-addressed store.
- Gateway-side payload logging is outside this plugin's control.
- Response masking applies when a block closes; the durable log and later requests
  see the masked text, while an already-rendered delta may have shown the original.

## 许可证 / License

MIT
