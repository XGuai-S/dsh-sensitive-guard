# 自定义插件市场索引

本目录提供一个符合 DSH plugin market index **format 1** 的索引文件，让 `dsh-sensitive-guard` 可被插件市场发现并安装，无需等待官方榜单收录。

## 文件

- `index.json` — 索引文档（已用 DSH 内置校验器 `parseMarketIndex` 验证通过）
- `HOWTO.md` — 本说明

## 安装指向

索引里的版本指向精确 commit：

```
git+https://github.com/XGuai-S/dsh-sensitive-guard.git#203cbdff9fa809c0fe5adff27da283dc09fa486d
```

## 使用它（三种方式）

### 1. 通过 DSH 插件市场 UI（推荐）

在 **Plugins / Discover** 页面，添加来源（Add source），填入本文件的 raw URL：

```
https://raw.githubusercontent.com/XGuai-S/dsh-sensitive-guard/main/market/index.json
```

添加后即可在市场中搜索到 `dsh-sensitive-guard` 并一键安装。

### 2. 通过命令行

```sh
dsh plugin --profile <name> add dsh-sensitive-guard
```

或固定到本索引指向的版本：

```sh
dsh plugin --profile <name> add github:XGuai-S/dsh-sensitive-guard#203cbdff9fa809c0fe5adff27da283dc09fa486d
```

### 3. 通过 API / 工具

`pluginMarket.setIndexes([url])` 注册索引；随后 `plugin_market` 工具即可列出该索引中的插件。
安装仍走 `pluginManager.installBundle`，需要相应审批。

## 维护

每次发版时更新 `index.json`：

1. `version` → 新版本号（精确 SemVer）
2. `source.commit` → 新版本的 40 位十六进制 commit SHA
3. `publishTimestamp` → 发布时刻的 Unix 秒
4. 保持 `engines.dsh` 与实际兼容范围一致

更新后，用 DSH 内置校验器验证：

```
parseMarketIndex(JSON.parse(fs.readFileSync('market/index.json','utf8')), indexUrl)
```

不抛异常即为有效。

## 为什么不用官方榜单

DSH.SO 精选榜是从 GitHub Star / npm 下载等六张排行榜各取前 200 合成的静态索引，且要求「可固定的精确版本」；新插件没有 star 和下载量时不会被抓取。自定义索引不受此限制，可立即使用。
