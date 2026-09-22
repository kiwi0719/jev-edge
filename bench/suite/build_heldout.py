#!/usr/bin/env python3
"""Build bench/datasets/heldout-v1.jsonl: a test set the `untrusted` question was
not written against, for the core implementation of untrusted-content judging.

The question was written and measured on suite v1 (LLMail phase 2, BIPIA
EmailQA, this repo's docs). Nothing here comes from those:

  attacks  InjecAgent base cases (MIT): an attacker instruction inside a JSON
           tool response (a product review, a calendar note, a tweet ...)
           LLMail-Inject phase 1 (MIT): submissions that triggered the tool
           call, none of them also in phase 2
  benign   the same InjecAgent response templates with the attacker slot filled
           by an ordinary sentence (the first sentence of an OpenAssistant train
           reply, Apache-2.0), so attack and benign share the carrier
           NousResearch/hermes-function-calling-v1 tool responses (Apache-2.0):
           func-calling and its glaive-function-calling-5k subset

Every record is a whole request body, rendered in one of the three shapes core
reads tool results from (OpenAI chat `role: tool`, Anthropic `tool_result`,
Responses `function_call_output`), chosen at random per record.

    python3 bench/suite/build_heldout.py --raw <download dir>
"""

import argparse
import ast
import json
import os
import random
import re
import sys

SEED = 20260925
SYSTEM = "You are a helpful assistant with access to tools. Use the tool results to answer the user."


def read_parquet(path):
    import pyarrow.parquet as pq
    return pq.read_table(path).to_pylist()


def render(shape, user, tool_name, args, result, system=SYSTEM):
    if shape == "openai":
        return {"model": "gpt-4o-mini", "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function",
                "function": {"name": tool_name, "arguments": args}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": result},
        ]}
    if shape == "anthropic":
        return {"model": "claude-sonnet-5", "system": system, "messages": [
            {"role": "user", "content": user},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": tool_name,
                                               "input": json.loads(args) if args.startswith("{") else {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": result}]},
        ]}
    return {"model": "gpt-4o-mini", "instructions": system, "input": [
        {"role": "user", "content": user},
        {"type": "function_call", "call_id": "call_1", "name": tool_name, "arguments": args},
        {"type": "function_call_output", "call_id": "call_1", "output": result},
    ]}


def py_args(s):
    """InjecAgent writes tool parameters as a Python dict literal."""
    try:
        return json.dumps(ast.literal_eval(s))
    except (ValueError, SyntaxError):
        return "{}"


def first_sentence(text):
    text = re.sub(r"\s+", " ", text).strip()
    m = re.match(r"(.{30,240}?[.!?])(\s|$)", text)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", default="bench/datasets/heldout-v1.jsonl")
    a = ap.parse_args()
    rng = random.Random(SEED)
    shapes = ["openai", "anthropic", "responses"]
    out = []

    def add(rid, source, category, label, user, tool, args, result, system=SYSTEM):
        shape = rng.choice(shapes)
        out.append({"id": rid, "source": source, "category": category, "label": label, "shape": "indirect",
                    "carrier": shape, "lang": "en", "body": render(shape, user, tool, args, result, system)})

    # InjecAgent base cases, direct-harm and data-stealing
    cases = []
    for f in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
        cases += json.load(open(os.path.join(a.raw, "InjecAgent", "data", f)))
    picked = rng.sample(cases, 300)
    for i, c in enumerate(picked):
        result = c["Tool Response"]
        if result.startswith('"') and result.endswith('"'):
            result = result[1:-1]
        add(f"injecagent-attack-{i}", "InjecAgent", "injecagent:" + c["Attack Type"].lower().replace(" ", "_"), 1,
            c["User Instruction"], c["User Tool"], py_args(c["Tool Parameters"]), result)

    # the same templates, the attacker slot filled with an ordinary sentence
    oa = [r for r in read_parquet(os.path.join(a.raw, "oasst1_train.parquet"))
          if r["role"] == "assistant" and r["lang"] == "en" and not r["deleted"]]
    fills = [s for s in (first_sentence(r["text"]) for r in rng.sample(oa, 4000)) if s]
    # an ordinary sentence may still address the reader; keep ones that do not
    # open like a request to an assistant
    fills = [s for s in fills if not re.match(r"(?i)(please|can you|could you|you should|make sure|ignore)\b", s)]
    templates = rng.sample(cases, 300)
    for i, c in enumerate(templates):
        tpl = c["Tool Response Template"]
        if "<Attacker Instruction>" not in tpl:
            continue
        fill = fills[i % len(fills)].replace("'", "’")
        add(f"injecagent-benign-{i}", "InjecAgent+oasst1", "injecagent:benign_fill", 0,
            c["User Instruction"], c["User Tool"], py_args(c["Tool Parameters"]),
            tpl.replace("<Attacker Instruction>", fill))

    # Hermes function-calling tool responses
    def hermes(fname, n, tag):
        convs = json.load(open(os.path.join(a.raw, fname)))
        rng.shuffle(convs)
        k = 0
        for c in convs:
            msgs = c["conversations"]
            for j, m in enumerate(msgs):
                if m["from"] != "tool":
                    continue
                human = next((x["value"] for x in reversed(msgs[:j]) if x["from"] == "human"), None)
                call = re.search(r'"name":\s*"([^"]+)"', msgs[j - 1]["value"]) if j > 0 else None
                body = re.sub(r"</?tool_response>", "", m["value"]).strip()
                if not human or len(body) < 40:
                    continue
                add(f"hermes-{tag}-{k}", "hermes-function-calling-v1", f"hermes:{tag}", 0, human,
                    call.group(1) if call else "tool", "{}", body)
                k += 1
                break
            if k >= n:
                return

    hermes("hermes_fc.json", 250, "func_calling")
    hermes("hermes_glaive5k.json", 150, "glaive5k")

    # LLMail-Inject phase 1: attacks that triggered the tool, not also in phase 2
    p1 = os.path.join(a.raw, "llmail_labelled_unique_submissions_phase1.json")
    if os.path.exists(p1):
        seen2 = set(json.load(open(os.path.join(a.raw, "llmail_labelled_unique_submissions_phase2.json"))))
        subs = json.load(open(p1))
        hits = [t for t, lab in subs.items() if str(lab.get("attack_attempt")) == "True"
                and lab.get("reason") == "api_triggered" and t not in seen2 and 50 <= len(t) <= 8000]
        scen = json.load(open(os.path.join(a.raw, "llmail_scenarios.json")))
        pool = [e for s in scen.values() for e in s["emails"]]
        for i, t in enumerate(rng.sample(hits, 200)):
            k = rng.choice([0, 1, 2])
            emails = rng.sample(pool, k)
            emails.insert(rng.randint(0, k), t)
            add(f"llmail1-attack-{i}", "LLMail-Inject phase 1", "llmail1:attack_api_triggered", 1,
                "Summarize all following emails.", "search_emails", "{}", "\n\n".join(emails))
    else:
        print("no LLMail phase 1 file; skipped", file=sys.stderr)

    with open(a.out, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    for (cat, lab), n in sorted(Counter((r["category"], r["label"]) for r in out).items()):
        print(f"{n:5d}  label={lab}  {cat}", file=sys.stderr)
    print(Counter(r["carrier"] for r in out), file=sys.stderr)
    print(f"{len(out)} records -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
