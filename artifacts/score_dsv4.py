#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Score the DeepSeek-V4 v2 full-arm pass with the SAME audited rules used for
the Qwen passes: stats_v2.rescore2 (verdict overlay + set membership) over the
253-task analysis set. TSA/AF1 read the harness-recorded first-call fields
(scorer-identical to the Qwen passes; the overlay affects only TS). Writes
cross_model_dsv4.json."""
import json, sys, os, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stats_v2 as S

runs = {}
for line in open('r3_dsv4_full_p1.jsonl', encoding='utf-8'):
    r = json.loads(line)
    runs[r['task']] = r

rows, ts_n, tsa_n, af1s, e2e = [], 0, 0, [], []
for t in S.TASKS:
    r = runs.get(t)
    if r is None:
        print('missing', t); continue
    ts = bool(S.rescore2(t, r))
    tsa = bool(r.get('tsa')); af1 = float(r.get('af1') or 0.0)
    ts_n += int(ts); tsa_n += int(tsa); af1s.append(af1)
    e2e.append(r.get('e2e_ms') or 0)
    rows.append({'id': t, 'ts': ts, 'tsa': tsa, 'af1': af1})

out = {
    'model': 'DeepSeek-V4', 'pass': 1, 'n': len(rows),
    'ts': round(100 * ts_n / len(rows), 1),
    'tsa': round(100 * tsa_n / len(rows), 1),
    'af1': round(statistics.mean(af1s), 3),
    'e2e_med': int(statistics.median(e2e)),
}
for pref, cls in (('A', 'asset'), ('L', 'logs'), ('T', 'disp'), ('O', 'org'),
                  ('S', 'stats'), ('P', 'proj'), ('X', 'cross')):
    sel = [r for r in rows if r['id'].startswith(pref)]
    if sel:
        out[f'cls_{cls}'] = {'n': len(sel),
                             'ts': round(100 * sum(r['ts'] for r in sel) / len(sel), 1)}
json.dump(out, open('cross_model_dsv4.json', 'w', encoding='utf-8'),
          indent=1, ensure_ascii=False)
print(json.dumps(out, ensure_ascii=False))
