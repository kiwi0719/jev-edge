# What jev-edge costs

**English** | [简体中文](cost.zh-CN.md)

Two numbers decide the bill: how much of your traffic reaches L2, and the provider's input price. L1 passes everything that is not a watched path with a natural-language body, and the fingerprint cache absorbs replays, so on a whole site the L2 share is typically a few percent; on a pure chat endpoint it is most requests.

```
monthly cost ≈ QPS × L2 share × 2.63M s/month × tokens per call × price per token
```

## Tokens per call

Measured on the live runs (`make live-full`, deepset/prompt-injections, `jev-latest`):

| template | deployment context | input tokens | output tokens |
|---|---|---|---|
| `injection` | no | 513 | 39 |
| `injection` | yes | 610 | 39 |

Add the `abuse` template and the per-call count rises slightly; the questions share one request. Longer user messages cost more: these figures are for the dataset's short prompts, and `rules.max_body_bytes` (64 KB) is the upper bound per call.

## Worked table

TypeSafe's published input price on 2026-09-22 was **$42 per billion input tokens**; no output price was listed, and at 39 tokens per call output is negligible at any plausible rate. **Verify the current price at [typesafe.ai](https://typesafe.ai/) before you plan**; this table will not be updated every time it changes.

At 610 input tokens per call:

| average QPS | 1% reaches L2 | 5% reaches L2 | 100% reaches L2 |
|---|---|---|---|
| 10 | $7 / month | $34 / month | $675 / month |
| 100 | $67 / month | $337 / month | $6,750 / month |
| 1,000 | $674 / month | $3,370 / month | $67,500 / month |

## Measure yours

`jev_tokens_total{direction="input"}` in `/_jev/metrics` gives you the real number after a day in `monitor` mode. `jev_requests_total{source="l2"}` over `jev_requests_total` is your L2 share.
