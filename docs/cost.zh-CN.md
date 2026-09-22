# jev-edge 要花多少钱

[English](cost.md) | **简体中文**

账单由两个数决定：你的流量里有多少会走到 L2，以及 provider 的输入 token 单价。L1 只把"受监控路径上、带自然语言 body"的请求送往 L2，其余一律直接放行；重复的请求又会命中指纹缓存。所以按整站流量算，走到 L2 的通常只有百分之几；如果是一个纯聊天接口，那大部分请求都会走到 L2。

```
monthly cost ≈ QPS × L2 share × 2.63M s/month × tokens per call × price per token
```

## 每次调用用多少 token

下表来自真实运行的实测（`make live-full`，数据集 deepset/prompt-injections，模型 `jev-latest`）：

| 模板 | 部署上下文 | 输入 token | 输出 token |
|---|---|---|---|
| `injection` | 无 | 513 | 39 |
| `injection` | 有 | 610 | 39 |

再加上 `abuse` 模板，每次调用的 token 会稍多一点，两个问题放在同一个请求里。用户消息越长，花得越多：上面的数字对应的是这个数据集里的短 prompt，每次调用的上限是 `rules.max_judge_bytes`（32 KiB 文本）。超过这个长度的文本会先被切成送审窗口再送往 L2（切了多少次看 `jev_window_total`），所以再大的 body，放进 prompt 的文本也最多 32 KiB。

打开 `untrusted` 之后（见[检索内容](design.zh-CN.md#检索内容)），带 tool 返回或 `untrusted.fields` 的请求会多一次调用：只把检索内容单独送审，问的是 `untrusted` 问题，不带部署上下文。这类请求要按两次调用来算；对话历史里重复出现的同一个 tool 返回，从第二轮起就会命中缓存。

## 算一笔账

TypeSafe 在 2026-09-22 公布的输入价格是 **每十亿输入 token 42 美元**，没有列出输出价格；每次调用只有 39 个输出 token，不管单价多少都可以忽略。**做预算之前，先去 [typesafe.ai](https://typesafe.ai/) 确认当前价格**，这张表不会跟着价格变动更新。

按每次调用 610 个输入 token 计算：

| 平均 QPS | 1% 走到 L2 | 5% 走到 L2 | 100% 走到 L2 |
|---|---|---|---|
| 10 | 每月 $7 | 每月 $34 | 每月 $675 |
| 100 | 每月 $67 | 每月 $337 | 每月 $6,750 |
| 1,000 | 每月 $674 | 每月 $3,370 | 每月 $67,500 |

## 量一量你自己的

在 `monitor` 模式下跑一天，`/_jev/metrics` 里的 `jev_tokens_total{direction="input"}` 就是真实的 token 用量；`jev_requests_total{source="l2"}` 除以 `jev_requests_total`，就是你的 L2 占比。
