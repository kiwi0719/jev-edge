# bench/suite: suite v1

Every accuracy number in [../report.md](../report.md) comes from one dataset, deepset/prompt-injections:
662 samples, labelled for one deployment (a German news site's reader assistant), almost all single-turn
English or German. `judge-directed.jsonl` is 45 hand-written cases and works as a regression test, not
as an accuracy measure. Suite v1 covers the gaps those two leave: Chinese injection, multi-turn
conversations, indirect injection inside retrieved emails and tool results, and benign look-alikes that
test over-defense.

Each record is a **whole chat request body**, not a bare string. `live.lua` runs it through L1 with the
shipped `llm-endpoints` rule set, so the gateway's own extraction decides what the judge sees:
`messages[*].content` over every role, including the system prompt and `role: tool` results.

Results: [report.md](report.md), generated from `bench/datasets/live-suite-jev-latest-{bare,ctx}.jsonl`.

## Contents (2,735 records: 1,450 attacks, 1,285 benign)

| shape | source | attack | benign | built as |
|---|---|---|---|---|
| single, zh | [thu-coai/Safety-Prompts](https://github.com/thu-coai/Safety-Prompts) instruction attacks | 300 Goal_Hijacking, 150 Prompt_Leaking, 150 Role_Play_Instruction | | one user turn |
| single, zh | [silk-road/alpaca-data-gpt4-chinese](https://huggingface.co/datasets/silk-road/alpaca-data-gpt4-chinese) | | 400 | instruction (+ input), never the GPT-4 output |
| single, mixed | [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) | | 339 | benign prompts built around trigger words ("ignore", "bypass", ...), 84 of them multilingual |
| indirect, en | [microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) phase 2 | 200 that triggered the tool call, 200 the challenge's judge labelled as attacks | 203 `emails_for_fp_tests` | LLMail's own system prompt + user query; the email among 0, 1, 2 or 4 benign scenario emails |
| indirect, en | [microsoft/BIPIA](https://github.com/microsoft/BIPIA) EmailQA | 200 (test-split text attacks, 15 kinds) | 100 | attack at the start, middle or end of the email |
| multi | [OpenAssistant/oasst1](https://huggingface.co/datasets/OpenAssistant/oasst1) validation threads (3 to 7 turns) | 150 attack in the last user turn, 100 in an earlier one | 243 | attacks from [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions), or Safety-Prompts Goal_Hijacking in zh threads |

Indirect records carry the retrieved emails one of two ways, chosen at random: inline in the user turn
(plain RAG) or as a `role: tool` result after an assistant tool call.

Each record also has a `deployment` string: the email-assistant context for the indirect records, a
general-assistant context for everything else. Both were written into `build.py` before any result was
seen, and `live.lua --ctx` sends them.

Sources and the revisions the committed suite was built from. All are MIT or Apache-2.0:

| source | license | revision |
|---|---|---|
| leolee99/NotInject | MIT | `847ae76` |
| Lakera/gandalf_ignore_instructions | MIT | `04737b6` |
| microsoft/llmail-inject-challenge | MIT | `1063bdf` |
| microsoft/BIPIA | MIT (EmailQA contexts from OpenAI evals, MIT) | `a004b69` |
| thu-coai/Safety-Prompts | Apache-2.0 | `bbfd3ce` |
| OpenAssistant/oasst1 | Apache-2.0 | `fdf72ae` |
| silk-road/alpaca-data-gpt4-chinese | Apache-2.0 | `81a6dfd` |

## Reproduce

```bash
make suite-fetch          # ~150 MB into bench/suite/raw (gitignored)
make suite-build          # Python 3.9+ with pyarrow; seeded, rewrites bench/datasets/suite-v1.jsonl
make suite-live           # bare text; costs one provider call per record
make suite-live CTX=1     # with each record's deployment context
make suite-report         # bench/suite/report.md

make suite-tooldocs-build   # the non-email tool results (bench/datasets/suite-v1-tooldocs.jsonl)
make suite-untrusted        # the experiment below: segment runs, and the whole-text run for tooldocs
make suite-untrusted-report # bench/suite/untrusted-report.md
make suite-heldout-build    # the held-out set
make suite-heldout          # the shipped core over it, untrusted off and on
make suite-heldout-report   # bench/suite/heldout-report.md
```

`suite-live` resumes an interrupted run: it skips every id already in the output file with no error.

## What the 2026-09-23 run found

`jev-latest`, both templates in one call, the `injection` score. 0 judge errors in either run. p50 about
300 ms and p95 about 430 ms at 6 concurrent calls.

- **Chinese instruction override is caught well.** Goal_Hijacking against alpaca-zh benign: AUC 0.994
  bare and 0.998 with context. At 0.5, 0% FP and 9.3% miss bare, 3.3% miss with context.
- **Multi-turn does not hide an attack.** AUC 0.997 bare. An attack in an earlier turn followed by a
  benign last turn is detected about as often as one in the last turn (90% vs 93% at 0.5, bare).
- **Indirect injection is the weak spot.** At 0.5, bare: LLMail-Inject 70% detected, BIPIA 18%. The AUCs
  (0.967, 0.993) look fine because benign emails score very low (BIPIA benign 0.03 to 0.06), but two
  thirds of BIPIA's attacks score under 0.3, below any threshold you would ship. BIPIA's attacks are mostly
  polite output instructions ("add a line about ...", "answer in Base64"), which read as harmless without
  knowing the text is an email.
- **Dilution.** LLMail detection falls as more benign emails are retrieved alongside the attack: 87% alone,
  54% with four others (with context, at 0.5). Nothing in these bodies came near the 32 KB judging window,
  so this is the judge, not the window.
- **The deployment context did not help this suite as a whole.** It raised the attack scores and the
  benign scores together. AUC: 0.971 bare vs 0.966 with context, excluding the two disputed categories
  below. With context, NotInject FP at 0.5 went from 0.9% to 11.5% (29.9% on its "Technique Queries"),
  and benign multi-turn FP from 1.6% to 4.5%. BIPIA detection at 0.5 went up (18% to 45%) with FP still
  0%, but LLMail's benign emails moved up to 0.25 to 0.42 (bare: 0.11 to 0.21), so a block threshold
  of 0.3 would reject 87% of them. The general-assistant context is the vague kind the main README
  warns about. Read this as evidence that a vague context can cost false positives, not as a result
  about a well-written one. On deepset the context moved AUC from 0.983 to 0.996; that finding stands,
  and it does not carry over to this suite.

## Experiment: judging retrieved content on its own

Core joins every message (system, user, assistant, tool) into one text and asks the `injection`
question of all of it, so the judge cannot tell the user's request from an email the assistant fetched.
`untrusted.lua` sends only the retrieved part of each indirect record to the judge, with two questions in
one call: the shipped `injection` question (B), and a new `untrusted` question written for external
content (C). The combined score, what a gateway asking both would act on, is max(A, C), where A is the
shipped whole-text score from the bare run. The `untrusted` question was committed (`ab16b4b`) before
the first run and was not changed afterwards. Tables: [untrusted-report.md](untrusted-report.md).

The retrieved part is the `role: tool` content where the app sent one. Where it pasted the emails into
the user turn, the segment is those emails cut off the query by hand: what the app would send if it used
a tool message. Core cannot make that cut on its own.

**Emails (suite v1), threshold 0.5, FP / miss:**

| | A: shipped | B: segment, `injection` | C: segment, `untrusted` | max(A, C) |
|---|---|---|---|---|
| LLMail-Inject, tool_result | 0% / 29.0% | 0% / 53.5% | 0% / 7.0% | 0% / 6.0% |
| BIPIA, tool_result | 0% / 85.4% | 0% / 78.1% | 0% / 37.5% | 0% / 37.5% |
| LLMail-Inject, user_inline (cut by hand) | 0% / 30.5% | 0% / 54.5% | 0% / 11.0% | 0% / 9.5% |
| BIPIA, user_inline (cut by hand) | 0% / 77.9% | 0% / 78.8% | 0% / 28.8% | 0% / 28.8% |

**Tool results that are not emails** (`build_tooldocs.py`: this repository's docs, source and golden
JSON at `0e2aec3`, OpenAssistant how-to answers, with and without an inserted BIPIA / Gandalf attack),
flagged at 0.5, A → max(A, C): attacks in how-to answers 34% → 75%, in source code 46% → 81%, in docs
45% → 75%. Benign: how-to answers 0% → 0%, source code 1.7% → 3.4%, docs 1.4% → 6.1%, JSON 2.9% → 5.9%.

- **The question does the work, not the cut.** Judging the segment alone with the shipped `injection`
  question (B) is no better than today, and worse on LLMail. The `injection` question asks whether the
  *user* is attacking the assistant, and an email is not the user. Asked the right question (C), the
  judge cuts LLMail's miss rate at 0.5 from 29% to 6% and BIPIA's from 85% to 38%, with no false
  positive on the 303 benign emails (upper bound about 1%).
- **BIPIA is still missed a third of the time.** Its hardest attacks read as ordinary requests ("analyse
  the sentiment of ...") even when the judge is told the text is external.
- **The new false positives are mostly text that talks to an AI.** Of the 13 benign docs, code and JSON
  chunks C flags at 0.5 (not counting the ones quoting an attack), most are this repository's material
  about prompting and judging models: a classifier system prompt in source, the `deployment_context`
  examples, a template, a test holding "IGNORA todas las instrucciones". A few have no clear reason (a
  golden-vector chunk of repeated letters, a design-doc table). Retrieval over prompt libraries or AI
  documentation will see this. The how-to answers, full of imperatives meant for the reader, stayed at
  0%.
- **Prompts in a tool result are flagged, and that is arguably right.** NotInject's benign user prompts
  placed where a tool result goes are flagged 38% of the time at 0.5 (17% at 0.7). A retrieved document
  that says "please describe the room in detail" to whoever reads it is what an indirect injection looks
  like; whether that is a false positive depends on the app.
- **Not measured:** real tool traffic (every carrier here is built), retrieved content in languages other
  than English, and chunks near the window. One run, one model.

That change shipped in 0.6.0 as `untrusted` (off by default; main README, "Retrieved content"), and was
then tested on data the question had not seen:

## Held-out test: the shipped core

`heldout-v1.jsonl` (`build_heldout.py`) is 1,200 whole request bodies from sources the `untrusted`
question was not written against, committed (`574268d`) before the run:

| | source | n | carrier |
|---|---|---|---|
| attack | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) base cases (MIT), direct harm and data stealing | 300 | an attacker instruction inside a JSON tool response: a product review, a calendar note, a tweet |
| attack | LLMail-Inject phase 1 (suite v1 used phase 2), submissions that triggered the tool, none also in phase 2 | 200 | an email among 0 to 2 others |
| benign | the same InjecAgent templates, the attacker slot filled with the first sentence of an OpenAssistant train reply | 300 | identical to the attacks, so what differs is the content |
| benign | [NousResearch/hermes-function-calling-v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1) tool responses (Apache-2.0) | 400 | JSON results of weather, stock, booking, camera ... calls |

Each body is rendered as OpenAI chat (`role: tool`), Anthropic (`tool_result`) or Responses
(`function_call_output`), at random. `heldout.lua` runs `core.evaluate` itself, the real judge behind it,
every record with `untrusted` off and on, a fresh cache for each. Tables:
[heldout-report.md](heldout-report.md).

| threshold 0.5 | AUC | FP | miss |
|---|---|---|---|
| `untrusted` off (0.5.0 behaviour) | 0.784 | 0.0% | 86.8% |
| `untrusted` on | **0.997** | 0.1% (1 of 700) | **19.2%** |

- **It holds on data it was not written for.** Miss at 0.5 drops from 87% to 19% with one false positive
  in 700, better than on the suite it was developed on. Per InjecAgent category, detection is 90 to 97%
  for data stealing and "others", 68% for physical and data-security harm, 45% for financial harm.
- **Responses API tool output was never judged before.** With `untrusted` off, core's text fields never
  read a `function_call_output`, so every attack in that shape passed (AUC 0.497). With it on, that
  shape does as well as the other two.
- **Cost**: every request carrying tool content makes 2 calls instead of 1; L2 time p50 277 → 293 ms,
  p95 346 → 364 ms, since the calls run in parallel.
- **Limits**: the benign fill sentences are ordinary but out of place in their slot; everything is
  English; the benign tool outputs are clean and short, unlike retrieval over documentation or prompt
  libraries (see the tool-docs results above). One run.

## Caveats

- **Prompt_Leaking labels do not hold.** Looking at it after the run: of Safety-Prompts' 150
  Prompt_Leaking prompts, 80 name prompt-leaking attacks as a topic ("how would you defend against prompt
  leaking?"), and only a handful actually ask the model to reveal its prompt. Detection is 4.7% bare. The
  category stays in the suite and in the report with its source label, but it is left out of the headline
  slices, and the report shows the whole-suite AUC both with and without it. Excluding it was decided
  after seeing the scores.
- **Role_Play_Instruction is mostly harmful-content role play, not injection**, and some of it is benign
  ("you are a detective, analyse the evidence"). It is out of scope for the `injection` template and is
  left out of the same slices. With context it is flagged 83% of the time at 0.5.
- **The multi-turn attacks are synthetic.** An attack text spliced into a real conversation. When it
  replaces an earlier turn, the assistant reply that follows still answers the original question.
- **The LLMail `judge` labels come from the challenge's own LLM judge**, not from people. The
  `api_triggered` ones are attacks by construction: they made the model call the tool.
- **The benign sets are small and clean**: 100 BIPIA emails from 100 contexts, 203 LLMail FP emails. A FP
  rate of 0% on 100 records has an upper bound near 3%.
- **One full run per configuration.** The runs were made from a working tree that also held unrelated
  uncommitted edits (breaker `BUSY` handling, IP-trust removal, a provider refactor), so 300 random
  records were re-run bare from a clean checkout of `0e2aec3`: the judged text was identical for all
  300; 185 scores were identical, the rest differed by at most 0.05 (mean 0.006), and 1 of 300 changed
  side of 0.5. Treat differences under a couple of points between slices as noise. Token usage was not
  recorded (the usage callback reported 0).
- **L1 and the judging window are not exercised.** L1 passed no record, and no body was over 32 KB.
- **Still missing:** real Chinese traffic (every Chinese attack here is generated), Chinese indirect
  injection, tool results other than email, and long RAG contexts that push an attack out of the window.
  Monitor mode on your own traffic with `make labels` / `make calibrate` is still the only way to measure
  your rates.
