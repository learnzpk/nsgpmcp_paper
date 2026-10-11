#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clean UCR: numeric/identifier claims in final answer not present in the
observation window actually seen by the model (trace obs[:8000]) or the query.
Filters year/ordinal/small-index noise and enum words."""
import json, re, sys

NUM = re.compile(r'(?<![\w.])\d[\d,]*(?:\.\d+)?(?:%|万|条|个|次|天|人|页)?(?![\w.])')
IDT = re.compile(r'\b(?:INFO|NS|PM|MAINTAIN|WZ|EXAM)_?[\dA-Z]{4,}\b|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b|\b[a-z0-9][a-z0-9.\-]*\.(?:***\.edu\.cn|edu\.cn|cn|com|net)\b', re.I)
STOP = {'information', 'hardware', 'informatization', 'center', 'online', 'offline',
        'level', 'page', 'total', 'status', 'name', 'type', 'time', 'date', 'data',
        'asset', 'assets', 'result', 'results', 'examples', 'ipaddress', 'ip'}

def claims(ans):
    out = set()
    for m in NUM.finditer(ans):
        tok = m.group(0).rstrip('.,%万条个次天人人页')
        if len(tok) < 2 or tok.lower() in STOP:
            continue
        d = tok.replace(',', '')
        if d.isdigit():
            if len(d) <= 4 and 1900 <= int(d) <= 2100: continue   # years
            if len(d) <= 2 and int(d) <= 31: continue             # indexes/days
            if len(d) == 12: continue                             # unix timestamps
        out.add(tok)
    for m in IDT.finditer(ans):
        if m.group(0).lower() not in STOP:
            out.add(m.group(0))
    return out

def grounded(tok, hay):
    t = tok.strip().rstrip('%')
    return any(c and c in hay for c in {t, t.replace(',', ''), t.replace(' ', '')})

def ucr(path, tasks):
    tot = ung = 0
    ex = {}
    for l in open(path, encoding='utf-8'):
        r = json.loads(l)
        if not r['trace'] or 'obs' not in r['trace'][0]:
            continue
        hay = ' '.join(m.get('obs', '') for m in r['trace']) + ' ' + tasks[r['task']]['query']
        for c in claims(r['final'] or ''):
            tot += 1
            if not grounded(c, hay):
                ung += 1
                ex.setdefault(r['task'], []).append(c)
    return ung, tot, ex

if __name__ == '__main__':
    tasks = {t['id']: t for t in json.load(open('tasks_v1.json', encoding='utf-8'))}
    res = {}
    for arm in sys.argv[1:] or ['full', 'ablated']:
        u, t, ex = ucr(f'results_{arm}.jsonl', tasks)
        res[arm] = {'ungrounded': u, 'total': t, 'ucr': round(u / t, 3) if t else None,
                    'by_task': {k: v[:6] for k, v in ex.items()}}
    print(json.dumps(res, ensure_ascii=False, indent=1))
