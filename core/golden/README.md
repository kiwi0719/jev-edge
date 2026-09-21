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
| `extract.json` | `extract` | text extraction from JSON, form and text bodies by content type and field paths |
| `rules.json` | `rules` | every L1 decision of the shipped `llm-endpoints` rule set, including one positive per `always_suspect` pattern |
| `policy.json` | `policy` | score to action / label / async mapping, threshold edges, error and skipped events |
| `verdict.json` | `verdict` | verdict defaults, clamping, header rendering, reason encoding |
| `evaluate.json` | `evaluate` | the whole pipeline with every IO scripted: L1, cache, breaker, L2, policy, cache writes, prompt contents |

Each file is `{ format_version, core_version, suite, generated_by, cases: [ { name, input, expect } ] }`.
`format_version` changes only when the shape of `input` or `expect` changes; `core_version` records which core produced the file and is informational.

## Building a context from `input`

An implementation replays a case by constructing its IO from `input` exactly as `core/spec/golden_spec.lua` does:

- **`cache`**: a key-value map preloaded into the cache double. Reads return the stored value; writes are recorded as `{ value, ttl }` under the key and appear in `expect.cache_writes`.
- **`clock`**: the value the injected clock returns, in seconds. It never advances inside a case, so `l2_ms` is always 0.
- **`rules`**: rule set ids, loaded from `rules/<id>`.
- **`config`**: deep-merged over `core/defaults.lua`.
- **`judge`**: `{ answers }` returns that map from the judge call; `{ error }` returns `nil, error`. `expect.judge_calls` counts calls and `expect.prompt` records the prompt the core built: `text`, `context` and the sorted question names.
- **`breaker`**: `null` means no breaker injected. `"open"` is a breaker whose open period has not elapsed at `clock`; `"closed"` is a healthy one.
- **`hash`** is the reference djb2 (`normalize.djb2`), **`json_decode`** is any RFC 8259 parser, **`re_find`** is a case-insensitive regex search.

## What parity covers and what it does not

**Covered by the vectors** (must match byte for byte):

- normalisation, fingerprinting with the reference hash, text extraction
- L1 decisions: path watch list, method and content-type filters, body size bounds, reputation lookups, `always_suspect` patterns, natural-language length
- policy: thresholds, mode, the async flag, error and skipped events
- verdict structure, header names and values, reason encoding and truncation
- the order in which the pipeline consults L1, cache, breaker and L2, and what it writes to the cache

**Not covered** (platform semantics; each adapter documents its own):

- cache TTL precision and eviction (a shared dict, KV and the Cache API expire differently)
- breaker window statistics across workers or isolates; only "open skips L2, closed calls L2" is pinned
- the adaptive timeout's numeric value; only that `jev.timeout_ms` is what the judge receives
- the production hash (OpenResty uses `ngx.crc32_long`; a port may use any function, as long as its own adapters agree with each other); the vectors use djb2 so the *normalised text* is what is compared
- HTTP transport: provider request bodies, retries, header casing on the wire

## Regex portability

`always_suspect` patterns are written in the intersection of PCRE and JavaScript RegExp: `\b`, `\s`, character classes, non-capturing groups, bounded repetition, alternation. No lookbehind, no possessive quantifiers, no `\Q...\E`, no inline flags. `rules.json` carries one positive sample per pattern so a divergence between engines fails a named case rather than a user's traffic. Adding a pattern means adding its sample to `core/golden/gen.lua`.
