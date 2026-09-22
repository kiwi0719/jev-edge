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
