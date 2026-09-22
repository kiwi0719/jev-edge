#!/bin/sh
# Download the sources bench/suite/build.py reads into $1 (default bench/suite/raw,
# gitignored). ~150 MB. Every source is MIT or Apache-2.0; see README.md.
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
echo "sources in $RAW"
