"""Fit LAYA_TEMPERATURE for a fine-tuned Laya model.

A fine-tuned classifier's raw scores are usually over-confident: most land
near 0 or 1 whatever the real odds are, and a block_threshold picked on them
moves the error rates in large jumps. Temperature scaling divides the logit by
one number T, fitted by minimising the log loss on labelled data the model did
NOT see in fine-tuning. It changes no ranking (AUC is unchanged), only how far
the scores spread, so `noul` reads as a probability.

Runs the same backend, question wording and windowing as the server, in
process (no rounding, no HTTP):

    LAYA_BACKEND=onnx LAYA_MODEL_DIR=/model \\
      python3 fit_temperature.py heldout.jsonl [--questions questions.json] [--ctx]

heldout.jsonl: one object per line,
    {"text": "...", "label": 1}                     1 / true = attack, 0 / false = benign
    {"text": "...", "label": 0, "question": "abuse", "assistant": "A billing assistant."}
`question` defaults to injection; `assistant` is used with --ctx (the
deployment_context wording) and ignored otherwise. `question: untrusted`
(the retrieved-content question) is scored with the text alone even under
--ctx: the gateway asks it without the deployment context.

questions.json is the System One `questions` object the gateway sends,
default ../../conformance/questions.json (generated from core/templates):
{"plain": {"injection": {...}, ...}, "ctx": {...}}. Fit with the wording you
run: a temperature fitted on one wording says nothing about another.

Prints T, the log loss and the expected calibration error before and after,
and the line to put in the server's environment.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from laya_server import Scorer, load_backend, sigmoid  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_QUESTIONS = os.path.join(HERE, "..", "..", "conformance", "questions.json")


def nll(pairs, t: float) -> float:
    s = 0.0
    for z, y in pairs:
        p = min(max(sigmoid(z / t), 1e-12), 1 - 1e-12)
        s -= y * math.log(p) + (1 - y) * math.log(1 - p)
    return s / len(pairs)


def ece(pairs, t: float, bins: int = 10) -> float:
    """Expected calibration error: |mean score - attack rate| per score bin, weighted."""
    acc = [[0, 0.0, 0.0] for _ in range(bins)]
    for z, y in pairs:
        p = sigmoid(z / t)
        b = acc[min(int(p * bins), bins - 1)]
        b[0] += 1
        b[1] += p
        b[2] += y
    return sum(abs(b[1] - b[2]) for b in acc if b[0]) / len(pairs)


def fit(pairs) -> float:
    """Golden-section search on log T over [0.05, 20]; the log loss is unimodal in T."""
    lo, hi = math.log(0.05), math.log(20.0)
    g = (math.sqrt(5) - 1) / 2
    a, b = hi - g * (hi - lo), lo + g * (hi - lo)
    fa, fb = nll(pairs, math.exp(a)), nll(pairs, math.exp(b))
    for _ in range(80):
        if fa < fb:
            hi, b, fb = b, a, fa
            a = hi - g * (hi - lo)
            fa = nll(pairs, math.exp(a))
        else:
            lo, a, fa = a, b, fb
            b = lo + g * (hi - lo)
            fb = nll(pairs, math.exp(b))
    return math.exp((lo + hi) / 2)


# questions the gateway asks without the deployment context (core/init.lua
# plan()): a string state under --ctx too, as the server sees them
NO_CONTEXT = {"untrusted"}

LABELS = {"1": 1, "true": 1, "attack": 1, "malicious": 1, "0": 0, "false": 0, "benign": 0, "safe": 0}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data")
    ap.add_argument("--questions", default=DEFAULT_QUESTIONS)
    ap.add_argument("--ctx", action="store_true", help="use the deployment_context wording and each line's assistant")
    args = ap.parse_args(argv)

    if not os.path.exists(args.questions):
        sys.stderr.write(f"{args.questions} not found: pass --questions with conformance/questions.json "
                         "from the jev-edge release you run\n")
        return 2
    with open(args.questions) as f:
        qs = json.load(f)["ctx" if args.ctx else "plain"]
    env = dict(os.environ)
    scorer = Scorer(load_backend(env),
                    temperature=1.0,
                    max_tokens=int(env.get("LAYA_MAX_TOKENS", "1024")),
                    overlap=int(env.get("LAYA_WINDOW_OVERLAP", "64")),
                    max_windows=int(env.get("LAYA_MAX_WINDOWS", "8")))

    pairs, skipped = [], 0
    with open(args.data) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            y = LABELS.get(str(rec.get("label")).lower())
            name = rec.get("question", "injection")
            if y is None or name not in qs:
                sys.stderr.write(f"line {n}: skipped (label {rec.get('label')!r}, question {name!r})\n")
                skipped += 1
                continue
            state = rec["text"]
            if args.ctx and name not in NO_CONTEXT:
                state = {"assistant": rec.get("assistant", ""), "user_message": rec["text"]}
            logits, _ = scorer.logits(state, {name: qs[name]})
            pairs.append((logits[name], y))

    pos = sum(y for _, y in pairs)
    if pos == 0 or pos == len(pairs):
        sys.stderr.write("need both attacks and benign examples\n")
        return 2
    if len(pairs) < 200:
        sys.stderr.write(f"warning: {len(pairs)} examples is few for a stable fit; aim for 1000+\n")

    t = fit(pairs)
    print(f"examples: {len(pairs)} ({pos} attacks, {len(pairs) - pos} benign), skipped {skipped}")
    print(f"log loss: {nll(pairs, 1.0):.4f} at T=1  ->  {nll(pairs, t):.4f} at T={t:.3f}")
    print(f"ECE:      {ece(pairs, 1.0):.4f} at T=1  ->  {ece(pairs, t):.4f} at T={t:.3f}")
    print()
    print(f"LAYA_TEMPERATURE={t:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
