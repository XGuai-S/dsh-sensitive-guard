# 设计说明 / Design notes

这份文档记录实现中的关键决策与踩过的坑。`README` 讲怎么用，这里讲**为什么这样实现**。

This document records the decisions that shaped the implementation. The README
says how to use the plugin; this says why it is built this way.

---

## 一、明文拦截为什么挂在 `typertGateway.dispatchRpc`

这是本项目最容易踩错的一处，值得完整记录。

### 问题

DSH 在 API 层 `agent.followup()` 就把用户输入写入 `agent/inbox/spliced`。这个
写入**早于** `agent/pre-step`，所以 pre-step 的脱敏只能保证 session 与请求不含
明文，无法阻止明文进 inbox。

实测证据（脱敏未生效时的会话日志）：

```
seq=2098  agent/inbox/spliced   优化一轮发布到GitHub上，/storage/emulated/0/AiWork/token.txt
seq=2102  user/message          优化一轮发布到GitHub上，{{LOCAL_PATH_101}}
```

inbox 是明文，session 是占位符——两者在同一次请求里，顺序固定。

### 两次失败的尝试

**尝试一：`connection/request` 事件**

它是 DSH 暴露的 HTTP 层瀑布，理论上早于一切存储。实际挂载后，日志里连诊断
输出都没有：

```
agent.followup() → inbox → pre-step → session
```

原因：Desktop 的 Web GUI 与服务端在**同一进程**，消息走进程内 fetch，不产生
真实 HTTP 请求，`connection/request` 根本不触发。

**尝试二：`ctx.get('typertGateway')` 直接包装**

`apply()` 执行时 `typertGateway` 服务尚未挂载，`ctx.get()` 返回 `undefined`，
包装被静默跳过。日志里没有 `【✅RPC前置拦截已启用】`，但也没有任何错误——这是
最危险的一类失败：**静默失效**。

### 正确的做法

```js
ctx.inject(['typertGateway'], (gatewayCtx) => {
  const gateway = gatewayCtx.typertGateway;
  const original = gateway.dispatchRpc;
  gateway.dispatchRpc = async function (endpoint, payload, signal, peer) {
    const outcome = interceptPayload(endpoint, payload, ...);
    return await original.call(this, endpoint, outcome.payload ?? payload, signal, peer);
  };
});
```

三个要点：

1. **用 `ctx.inject` 等待服务就绪**，不用 `ctx.get` 直接取。
2. **包装 `dispatchRpc` 而不是注册 interceptor**：`/api` 通道已被
   `typertGateway` 独占注册，二次注册会抛 `already has an interceptor`。
   `dispatchRpc` 正是那个 interceptor 的转发目标，位置等价。
3. **卸载时还原原方法**，避免 HMR 叠加多层包装。

### 验证方法

发一条含可识别敏感值的消息，然后解压会话日志检查：

```bash
node scripts/scrub-session.mjs --all --dry-run
```

成功时 `agent/inbox/spliced` 与 `user/message` 都是占位符；失败时前者是明文。

---

## 二、为什么 BLOCK 也走清洗而不是拒绝

早期版本命中阻断级内容直接 `{ kind: 'reject' }`，整条消息被拒。使用者反馈：
贴一段含手机号的日志，整条提问就没了，得重打一遍。

现在的做法是**清洗后继续**：敏感片段替换为占位符，其余文本照常进入流程。唯一
保留拒绝的是绕过攻击指令——它要求守卫停工，不属于可脱敏处理的内容。

这是一处**行为语义变更**，所以按语义化版本应该升主版本。

---

## 三、规则顺序是硬约束

`buildRules()` 的数组顺序即识别优先级，改顺序会导致真实误判。

| 位置 | 规则 | 为什么必须在这里 |
|---|---|---|
| 最前 | `name-id-pair` | 先跑证件规则会把号码换掉，姓名留在原地 |
| 中段 | 结构化 → 证件 → 凭证 → 地址 | 越具体越靠前 |
| 末尾 | `high-entropy` | 它最不具体；先跑会把路径、IP 前缀当随机串吃掉 |

这条顺序在 1.1.1 之前是错的：`high-entropy` 位于表中段，把
`/storage/emulated/0/DCIM/screenshot.png` 判成「可疑长串」而不是「本地路径」。

---

## 四、占位符一次写入，永不二次匹配

`maskText()` 的替换回调第一行：

```js
if (whole.includes('{{')) return whole;
```

没有这一条，`{{PRIVACY_ID}}` 会被后续规则再匹配一次，产出
`{{PRIVACY_ID_2}}` 这种编号变体。这是早期版本的真实 bug。

---

## 五、响应侧脱敏为什么可行

DSH 的 `BlockAssembler.push` 对 `block-end` 的处理是：

```js
partial.block = chunk.block;   // 整块覆盖
```

`assemble()` 一旦发现 `partial.block` 存在，直接返回它，**忽略此前累积的所有
`text-delta`**。所以在块闭合时发一个改写后的 `block-end`，下游拿到的就是脱敏
内容，不必追溯已发出的增量。

**代价**：已经渲染到界面的流式增量不回溯。进入会话日志与后续请求的内容是脱敏
后的，但界面上可能已经闪过原文。

---

## 六、失败一律放行

三处挂载点全部包在 `try/catch` 里，异常时返回原决策：

```js
} catch (error) {
  logger.warn(`扫描异常 ${error?.message}，已放行原决策`);
  return decision;
}
```

守卫自己出错绝不能让一个回合失败。副作用是静默失效不易察觉，因此所有诊断都
同时写 `stderr`（`ctx.logger` 在某些部署下被吞掉）。

---

## 七、内存与状态

会话级状态集中在 `SessionState`，四个 Map 全部懒创建。`session/disposed`
触发 `forget()` 释放——1.1.0 之前没有这一步，长跑的 Host 会为每个打开过的
会话永久保留注册表。

---

## 八、known limits

- **磁盘原图不删除**：附件存储内容寻址且不可变，涂改改变的是模型收到的内容，
  不是宿主保留的文件。
- **中转侧日志**：需在网关配置中关闭，插件无权控制。
- **流式增量不回溯**：见第五节。
- **绕过防护是启发式**：它拦的是明确要求守卫停工的指令，换一种说法可能绕过。
- **正则的固有局限**：覆盖列出的格式，不覆盖所有可能的写法。