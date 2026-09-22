#!/bin/sh
# Download the sources bench/suite/build.py reads into $1 (default bench/suite/raw,
# gitignored). ~650 MB with the held-out sources. Every source is MIT or Apache-2.0; see README.md.
set -eu
RAW=${1:-bench/suite/raw}
HF=https://huggingface.co/datasets
mkdir -p "$RAW"
cd "$RAW"

get() { [ -s "$1" ] || curl -fsSL -o "$1" "$2"; }

for p in one two three; do
  get notinject_$p.parquet "$HF/leolee99/NotInject/resolve/main/data/NotInject_$p-00000-of-00001.parquet"
done
for s in test validation train; do
  get gandalf_$s.parquet "https://huggingface.co/api/datasets/Lakera/gandalf_ignore_instructions/parquet/default/$s/0.parquet"
done
for f in emails_for_fp_tests.json labelled_unique_submissions_phase2.json scenarios.json system_prompt.json; do
  get llmail_$f "$HF/microsoft/llmail-inject-challenge/resolve/main/data/$f"
done
get oasst1_val.parquet "$HF/OpenAssistant/oasst1/resolve/main/data/validation-00000-of-00001-134b8fd0c89408b6.parquet"
get alpaca_zh.jsonl "$HF/silk-road/alpaca-data-gpt4-chinese/resolve/main/Alpaca_data_gpt4_zh.jsonl"
[ -d BIPIA ] || git clone -q --depth 1 https://github.com/microsoft/BIPIA.git
[ -d Safety-Prompts ] || git clone -q --depth 1 https://github.com/thu-coai/Safety-Prompts.git
# held-out set (build_heldout.py): InjecAgent, Hermes function calling, LLMail phase 1 (~450 MB), oasst1 train
[ -d InjecAgent ] || git clone -q --depth 1 https://github.com/uiuc-kang-lab/InjecAgent.git
get hermes_fc.json "$HF/NousResearch/hermes-function-calling-v1/resolve/main/func-calling.json"
get hermes_glaive5k.json "$HF/NousResearch/hermes-function-calling-v1/resolve/main/glaive-function-calling-5k.json"
get oasst1_train.parquet "$HF/OpenAssistant/oasst1/resolve/main/data/train-00000-of-00001-b42a775f407cee45.parquet"
get llmail_labelled_unique_submissions_phase1.json \
  "$HF/microsoft/llmail-inject-challenge/resolve/main/data/labelled_unique_submissions_phase1.json"
echo "sources in $RAW"
