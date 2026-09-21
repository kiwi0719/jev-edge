# jev-edge 花多少钱

[English](cost.md) | **简体中文**

账单由两个数决定：多少流量到达 L2，以及 provider 的输入价格。L1 放行所有不是"监控路径 + 自然语言 body"的请求，指纹缓存吸收重放，所以整站的 L2 占比通常是百分之几；纯聊天端点则是大多数请求。

```
月成本 ≈ QPS × L2 占比 × 2.63M 秒/月 × 每次调用 token 数 × 每 token 价格
```

## 每次调用的 token

在 live 跑上实测（`make live-full`，deepset/prompt-injections，`jev-latest`）：

| 模板 | 部署上下文 | 输入 token | 输出 token |
|---|---|---|---|
| `injection` | 无 | 513 | 39 |
| `injection` | 有 | 610 | 39 |

加上 `abuse` 模板，每次调用的 token 略增；两个问题共用一个请求。用户消息越长越贵：上面是数据集里短 prompt 的数字，`rules.max_body_bytes`（64 KB）是每次调用的上限。

## 算例

TypeSafe 在 2026-09-22 公布的输入价格是 **每十亿输入 token $42**；没有列输出价格，每次调用 39 个输出 token 在任何合理单价下都可以忽略。**做预算前先去 [typesafe.ai](https://typesafe.ai/) 核对当前价格**，这张表不会随价格变动而更新。

按每次调用 610 个输入 token：

| 平均 QPS | 1% 到达 L2 | 5% 到达 L2 | 100% 到达 L2 |
|---|---|---|---|
| 10 | $7 / 月 | $34 / 月 | $675 / 月 |
| 100 | $67 / 月 | $337 / 月 | $6,750 / 月 |
| 1,000 | $674 / 月 | $3,370 / 月 | $67,500 / 月 |

## 量你自己的

`monitor` 模式跑一天后，`/_jev/metrics` 里的 `jev_tokens_total{direction="input"}` 就是真实数字。`jev_requests_total{source="l2"}` 除以 `jev_requests_total` 是你的 L2 占比。
