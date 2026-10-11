#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Section 7.1 drift check: compare original frozen _ref with post-block re-freeze.
Scorable-after test mirrors gen_suite validate exemptions (empty payload / write)."""
import json

WRITE = ('add_black_ip', 'add_black_dns')
a = {t['id']: t for t in json.load(open('tasks_v2.json', encoding='utf-8'))}
b = {t['id']: t for t in json.load(open('tasks_v2_refrozen.json', encoding='utf-8'))}
assert set(a) == set(b), 'task id sets differ'

ident = changed = 0
unscored = []
for tid, t in a.items():
    ref0, ref1 = t.get('_ref', ''), b[tid].get('_ref', '')
    if ref0 == ref1:
        ident += 1
        continue
    changed += 1
    if t['gold_tool'] in WRITE or ref1.startswith('SIMULATED') or ref0.startswith('SIMULATED'):
        continue  # write tasks: simulated payload, nothing to drift
    empty1 = ('"total": 0' in ref1) or ('"results": []' in ref1) or ('"error"' in ref1)
    req = [k.lower() for k in (t.get('required_all') or [])]
    any_ = [k.lower() for k in (t.get('required_any') or [])]
    ok = all(k in ref1 for k in req) and (not any_ or any(k in ref1 for k in any_) or empty1)
    if not ok:
        unscored.append(tid)

print(json.dumps({
    'n': len(a), 'identical': ident, 'changed': changed,
    'verdict_tokens_broken_by_drift': unscored,
}, ensure_ascii=False))
for tid in unscored[:10]:
    t = a[tid]
    print('--', tid, t['gold_tool'])
    print('   req:', t.get('required_all'), 'any:', (t.get('required_any') or [])[:4])
    print('   ref1 head:', b[tid].get('_ref', '')[:160].replace('\n', ' '))
