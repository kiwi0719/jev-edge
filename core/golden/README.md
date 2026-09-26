# Golden vectors

The behavioural contract for `core/`. Every implementation of core, the Lua
one in this directory's parent and the TypeScript one planned for the
Cloudflare Worker, must reproduce these files exactly. A threshold tuned on
one gateway then means the same thing on every other.

```
make golden          regenerate *.json from the Lua core (after a deliberate change)
make golden-check    fail if the committed files differ from what core produces (CI)
busted               core/spec/golden_spec.lua replays the files against the Lua core
```

Rule for contributors: a PR that changes core behaviour regenerates the
vectors in the same PR and the diff is reviewed like code. A PR whose
`golden-check` fails without a regenerated file is a behaviour change nobody
meant to make.

## Files

| file | suite | what it pins down |
|---|---|---|
| `normalize.json` | `normalize` | `normalize()` text canonicalisation and `fingerprint()` with the reference djb2 hash |
| `extract.json` | `extract` | text extraction and the detected `kind` (`json`, `form`, `multipart`, `text`, `binary`, `none`): the body decides the format, the content type is a hint; `tokens` (present only when true) when a text field holds token ids, a number that is an item of a list |
| `rules.json` | `rules` | every L1 decision of the shipped `llm-endpoints` rule set (`pass`, `block`, `suspect`, `unjudgeable`), including one positive per `always_suspect` pattern, head-and-tail scanning past `max_body_bytes` and the `max_judge_bytes` window |
| `policy.json` | `policy` | score to action / label / async mapping, threshold edges, error and skipped events |
| `verdict.json` | `verdict` | verdict defaults, clamping, header rendering, reason encoding |
| `evaluate.json` | `evaluate` | the whole pipeline with every IO scripted: L1, cache, breaker, L2, policy (`policy.unjudgeable` included), cache writes, prompt contents, subject trajectory |

Each file is `{ format_version, core_version, suite, generated_by, cases: [ { name, input, expect } ] }`.
`format_version` changes only when the shape of `input` or `expect` changes; `core_version` records which core produced the file and is informational.

## Building a context from `input`

An implementation replays a case by constructing its IO from `input` exactly as `core/spec/golden_spec.lua` does:

- **`req`**: handed to core as-is: `method, path, headers, body, body_size, client_ip`, and where a case needs them `decoded` (the adapter decoded the `Content-Encoding`; `body` is the decoded body), `body_head` and `body_tail` (the first `max_body_bytes` and the last 64 KiB of a body past `max_body_bytes`, when that is all the adapter has), and `body_partial` (the gateway in front forwarded only the first part of the body: `body`, or `body_head`, is that part, scanned as a head whatever its size). A case with a whole `body` and a larger `body_size` leaves the head and tail cut to core; a case with neither `body` nor `body_head` is a gateway that forwarded headers only.
- **`cache`**: a key-value map preloaded into the cache double. Reads return the stored value; writes are recorded as `{ value, ttl }` under the key and appear in `expect.cache_writes`.
- **`clock`**: the value the injected clock returns, in seconds. It never advances inside a case, so `l2_ms` is always 0.
- **`rules`**: rule set ids, loaded from `rules/<id>`, or inline rule specs (a table with `extends = "<id>"` and the fields it overrides), resolved the way a config's `rules` list is (`rules.resolve`). The chunk cases use one with a 64-byte `max_judge_bytes` to keep the vectors small.
- **`subject.store`**: preloads the subject store (reputation counters); every write to it is recorded as `{ value, ttl }` in `expect.subject_store_writes` (`null` without a subject).
- **judge calls**: text judged in chunks makes one `judge.call` per chunk that missed the cache, in chunk order (`expect.judge_calls`); `expect.prompt` is the last prompt the core built. An adapter may run them in parallel through `judge.call_many`; the vectors pin the sequential order.
- **`config`**: deep-merged over `core/defaults.lua`.
- **`judge`**: `{ answers }` returns that map from the judge call; `{ error, kind }` returns `nil, error, kind` (`kind` may be absent: a judge that does not classify its errors). `expect.judge_calls` counts calls and `expect.prompt` records the prompt the core built: `text`, `context` and the sorted question names.
- **`subject`**: `null` means no subject context injected at all. Otherwise `{ id, history }` is passed as `ctx.subject` together with a `record` sink that captures the single entry the core hands over; that entry (or `null`) is `expect.subject_record`. **`history` must change nothing**: several cases pass a non-empty one and expect the same verdict as their subject-less twin. This version records trajectories, it does not score on them.
- **`breaker`**: `null` means no breaker injected. `"open"` is a breaker whose open period has not elapsed at `clock`; `"half-open"` one whose open period ends at `clock`; `"closed"` is a healthy one, all over an empty store with the default breaker settings. The double records every call core makes on it (`allow`, `success`, `failure`, `release`), in order, as `expect.breaker.calls`, and its state after the request (`0` closed, `1` open, `2` half-open) as `expect.breaker.state` (`null` without a breaker).
- **`hash`** is the reference djb2 (`normalize.djb2`), **`json_decode`** is any RFC 8259 parser, **`re_find(subject, pattern, init)`** is a case-insensitive regex search, PCRE without UTF, that returns the 1-based inclusive **byte** span `from, to` (UTF-8 bytes, not UTF-16 indices) of the first match starting at or after byte `init` (1 when absent), or nothing. Core walks each pattern's matches with `init`; a matcher that ignores it returns the first span again and the walk stops there, so the cases with several hits over `max_judge_bytes` will not match. A bare truthy value still decides L1, but the judging window can then not place the hit either.

## What parity covers and what it does not

**Covered by the vectors** (must match byte for byte):

- normalisation, fingerprinting with the reference hash, text extraction
- L1 decisions: path watch list, method and `skip_content_types` / `content_types` filters, body size bounds, reputation lookups, `Content-Encoding` without `decoded`, format detection, head-and-tail scanning past `max_body_bytes`, `unjudgeable` and its reasons (`unjudgeable: token prompt` for token ids with nothing else to judge; `expect.tokens` when a text field holds them), `always_suspect` patterns, natural-language length, the `max_judge_bytes` window and the ` (window)` reason suffix
- policy: thresholds, mode, the async flag, error and skipped events; an `unjudgeable` L1 result is `skipped` with action `pass`, or `block` only when `policy.unjudgeable = "block"` (for token ids, or the rule's `token_prompts = "block"`) and the mode is `enforce`; token ids beside judged text block the same way before trust, cache and breaker, with no judge call, and otherwise leave the text judged as always; a `body_partial` request is `unjudgeable: partial body` when `policy.partial = "unjudgeable"`
- verdict structure, header names and values, reason encoding and truncation
- the order in which the pipeline consults L1, cache, breaker and L2, and what it writes to the cache
- what core reports to the breaker: a failure only for a judge error of kind `transport`, `timeout` or `unavailable` (or with no kind), a success for an answer, and a release for anything else (`rejected`, `unusable`, an answer with no scores, `max_inflight exceeded`, no call at all); the reason of a `rejected` or `unusable` error starts with its kind
- the subject trajectory entry: its fields, which exits produce one (every exit that made a decision; not L1 pass), and that a supplied `history` is ignored
- subject reputation: the points a verdict adds, and that a request judged in parts is charged for the subject's own text only, not for the tool definitions' score; the whole request's cache entry keeps what to charge as `rep` (its own text's score, or `false` when none of it was judged; absent when that is the request's score) and a hit on it charges the same

**Not covered** (platform semantics; each adapter documents its own):

- cache TTL precision and eviction (a shared dict, KV and the Cache API expire differently)
- breaker window statistics across workers or isolates; only "open skips L2, closed calls L2", what core reports and the state one report leaves are pinned
- the adaptive timeout's numeric value; only that `jev.timeout_ms` is what the judge receives
- the production hash (OpenResty and APISIX use SHA-256; a port may use any function that is collision-resistant, because the fingerprint keys the verdict cache and the trust store); the vectors use djb2 so the *normalised text* is what is compared
- HTTP transport: provider request bodies, retries, header casing on the wire
- reading the request body: where head and tail come from (memory, a temp file, a stream), `Content-Encoding` decoding and its libraries; core only sees the resulting `req`
- key order past the sort budget: the keys of the objects one extraction reads whole are sorted in UTF-8 byte order up to 20,000 of them; past that the Lua core emits them in `pairs()` order and the TypeScript core in insertion order. The judged text holds the same strings either way, but the fingerprints differ, and no vector covers it
- `fp_prefix_bytes` cutting sampled or logged text inside a character: Lua keeps the partial bytes, the TypeScript core cannot hold them in a string, and a JSON vector cannot hold them either; every other cut (window, hit context, chunks, the head past `max_body_bytes`) moves to a character boundary and is pinned

## Regex portability

`always_suspect` patterns are PCRE as `ngx.re` runs them with `ijo`: without UTF, so `\s` is an ASCII space, `.` and `{m,n}` count bytes, and `i` folds ASCII letters only. The TypeScript core translates each pattern into a RegExp run over the text's bytes that answers the same (non-ASCII literals as their bytes, `\xhh` as a byte). What does not translate: lookbehind, possessive quantifiers, `\Q...\E` and inline flags such as `(?i)`; a pattern the TypeScript core cannot compile counts as a hit on every text there, logged once, so keep to what both run. `rules.json` carries one positive sample per pattern so a divergence between engines fails a named case rather than a user's traffic. Adding a pattern means adding its sample to `core/golden/gen.lua`.
