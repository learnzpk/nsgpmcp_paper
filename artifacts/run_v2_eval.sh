#!/bin/bash
# v2 three-arm evaluation: full/ablated/bare x 2 passes. Resumable:
# a pass file with >=259 lines is skipped; harness resumes partial files.
cd "$(dirname "$0")"
set -a; source .env_eval; set +a
export no_proxy='*' NO_PROXY='*'
PY=/Users/learnzpk/.workbuddy/binaries/python/envs/default/bin/python
for spec in "full 1" "full 2" "ablated 1" "ablated 2" "bare 1" "bare 2"; do
  arm=$(echo "$spec" | cut -d' ' -f1)
  pass=$(echo "$spec" | cut -d' ' -f2)
  f="r2_${arm}_p${pass}.jsonl"
  have=$(wc -l < "$f" 2>/dev/null || echo 0)
  if [ "$have" -ge 259 ]; then echo "=== SKIP $arm p$pass (complete) ==="; continue; fi
  echo "=== ARM=$arm PASS=$pass $(date +%T) have=$have ==="
  $PY harness.py --tasks tasks_v2.json --mode run --arm "$arm" --out "$f" | grep -E 'SUMMARY|resume|Error' || echo "PASS FAILED $arm p$pass"
done
echo "ALL DONE $(date +%T)"
