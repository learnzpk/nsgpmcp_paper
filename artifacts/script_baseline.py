#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle-script baseline (reviewer M3): a rule script that knows each task's
gold tool and gold arguments and returns the tool payload verbatim as the
answer -- a strict UPPER bound on what hand-written scripts / direct API
automation could achieve on the suite, without any language model.
Scored with the same audited overlay as the arms. Write tasks (plan-mode
simulation) and the H suite's adversarial shapes are reported as not-answerable.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Mcp
import stats_v2 as S

m = Mcp(os.environ['MCP_URL'], os.environ['MCP_TOKEN'])
m.init()
WRITE = ('add_black_ip', 'add_black_dns')

res = {'v2': {}, 'H': {}}

# ---- v2 suite ----
ans = na = okc = 0
fails = []
for tid, t in S.TASKS.items():
    if t['gold_tool'] in WRITE:
        na += 1
        continue
    payload = m.call(t['gold_tool'], t['gold_args'])[:8000]
    ok = S.rescore2(tid, {'final': payload})
    ans += 1
    okc += int(ok)
    if not ok:
        fails.append(tid)
res['v2'] = {'answerable': ans, 'not_answerable_write': na, 'passed': okc,
             'rate': round(100 * okc / max(ans, 1), 1), 'fails': fails[:20]}
print('v2 script baseline:', json.dumps(res['v2'], ensure_ascii=False), flush=True)

# ---- H suite ----
TH = json.load(open('tasks_h.json', encoding='utf-8'))
ans = na = okc = 0
detail = []
for t in TH:
    gt, ga = t.get('gold_tool'), t.get('gold_args')
    if not gt or t.get('inject') or t['shape'] in ('ambiguity', 'window-cap', 'leading-negative') or not ga:
        na += 1
        detail.append([t['id'], 'n/a'])
        continue
    payload = m.call(gt, ga)[:8000]
    low = payload.lower()
    req = [k.lower() for k in t.get('required_all') or []]
    any_ = [k.lower() for k in t.get('required_any') or []]
    ok = all(k in low for k in req) and (not any_ or any(k in low for k in any_))
    ans += 1
    okc += int(ok)
    detail.append([t['id'], 'pass' if ok else 'fail'])
res['H'] = {'answerable': ans, 'not_answerable': na, 'passed': okc,
            'rate_on_answerable': round(100 * okc / max(ans, 1), 1), 'detail': detail}
print('H script baseline:', json.dumps(res['H'], ensure_ascii=False), flush=True)

json.dump(res, open('script_baseline.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('done')
