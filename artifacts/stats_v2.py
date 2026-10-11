#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v2 suite aggregation and inference:
- per-arm medians across 2 passes (TS overall/per class, TSA, AF1, E2E)
- paired full-vs-ablated stats: exact McNemar (TS, TSA), bootstrap CI of AF1 diff
- McNemar power analysis at observed discordance rate
- latency pool (canonical pass 1, per arm), call counts
- qualitative scans: selection-miss confusion pairs, zero-result re-attempts,
  page declarations, bare-arm echo check, write interceptions, pass stability
"""
import json, math, random, statistics
from collections import defaultdict, Counter

TASKS = {t['id']: t for t in json.load(open('tasks_v2.json', encoding='utf-8'))}
# Suite audit: six template instances instantiated the project keyword slot
# empty (query reads: name contains ""), making them unanswerable as specified.
# Excluded from the analysis set for all arms and passes (reported in the paper).
EXCLUDE = {'P229', 'P230', 'P231', 'P232', 'P233', 'P234'}
TASKS = {k: v for k, v in TASKS.items() if k not in EXCLUDE}
NT = len(TASKS)
CLS = lambda tid: {'A': 'asset', 'O': 'org', 'L': 'logs', 'T': 'disp',
                   'S': 'stats', 'P': 'proj', 'X': 'cross'}[tid[0]]

# --- verdict-synonym overlay (scorer audit, second pass; see paper Section 7.4).
# Verdict vocabulary in gold payloads is Chinese-labeled; agents frequently relay the
# verdict in English. These translations are added to the verdict-token sets of the
# matching task shapes and applied identically to every arm and pass.
NEG_EN = ['not currently blocked', 'not blocked', 'is not blocked', 'no record', 'no matching',
          '0 record', 'none found', 'not in the', 'not listed', 'not present', 'absent', 'zero record',
          '0 matching', 'no block', 'no entries', 'no results', '0 entries', 'no hits']
WRITE_EN = ['submitted', 'registrat', 'added', 'existing', 'duplicat', 'simulat', 'pending', 'not executed']
SEC_EN = ['notification', 'rectification', 'record']

def is_ip_search(t):
    return (t['gold_tool'] == 'search_assets' and t['gold_args'].get('field') == 'ip')

def allowed_systems(t):
    """Adjudication for queries against shared/reverse-proxy addresses: production
    lists many systems at one address, so naming ANY ledger asset hosted there is
    correct. Allowed ids/names come from the frozen gold payload (not model output)."""
    import re as _re
    ref = t.get('_ref', '')
    ids = set(_re.findall(r'INFO_\d+', ref))
    names = set()
    for m in _re.finditer(r'"id":\s*"INFO_\d+"', ref):
        seg = ref[m.end():m.end() + 300]
        nm = _re.search(r'"name":\s*"([^"]{4,})"', seg)
        if nm:
            names.add(nm.group(1))
    return ids, names

def verdict_tokens(t):
    """(required_all, required_any, forbidden) after English-verdict overlay."""
    req = [k.lower() for k in (t.get('required_all') or [])]
    any_ = [k.lower() for k in (t.get('required_any') or [])]
    forb = [k.lower() for k in (t.get('forbidden') or [])]
    tool = t['gold_tool']
    if tool in ('add_black_ip', 'add_black_dns'):
        any_ += WRITE_EN
    elif tool in ('query_black_ips', 'query_black_dns') and not req and forb:
        any_ += NEG_EN
    elif tool == 'get_asset_security':
        any_ += SEC_EN
    if req == ['备案']:
        req = []            # verdict already carried by any_ ('filing'/'覆盖率'/'%')
    if is_ip_search(t):
        req = [t['gold_args']['keyword'].lower()]   # asset id -> set-membership below
    return req, any_, forb

def rescore2(tid, run):
    req, any_, forb = verdict_tokens(TASKS[tid])
    ans = (run['final'] or '').lower()
    ok = (all(k in ans for k in req)
          and (not any_ or any(k in ans for k in any_))
          and not any(k in ans for k in forb))
    if is_ip_search(TASKS[tid]):
        import re as _re
        a_ids, a_names = allowed_systems(TASKS[tid])
        got_ids = {i for i in _re.findall(r'INFO_\d+', run['final'] or '')}
        named = bool(got_ids & a_ids) or any(n in (run['final'] or '') for n in a_names)
        ok = ok and named
    return ok

def load(arm, p):
    runs = [json.loads(l) for l in open(f'r2_{arm}_p{p}.jsonl', encoding='utf-8')]
    d = {r['task']: r for r in runs if r['task'] in TASKS}
    assert len(d) == NT, (arm, p, len(d))
    for t, r in d.items():
        r['ts2'] = rescore2(t, r)      # audit-overlay verdict
    return d

def arm_stats(arm):
    ps = [load(arm, i) for i in (1, 2)]
    out = {}
    for name, k in (('ts', 'ts2'), ('tsa', 'tsa')):
        out[name] = [sum(bool(p[t][k]) for t in TASKS) / NT for p in ps]
    out['af1'] = [statistics.mean([p[t]['af1'] for t in TASKS]) for p in ps]
    out['e2e_med'] = [statistics.median([p[t]['e2e_ms'] for t in TASKS]) for p in ps]
    cls = defaultdict(list)
    for p in ps:
        for t, r in p.items():
            cls[CLS(t)].append(bool(r['ts2']))
    out['cls'] = {k: round(sum(v) / len(v), 4) for k, v in sorted(cls.items())}
    out['passes'] = ps
    return out

def pmcm(x, n):
    if n == 0:
        return 1.0
    k = min(x, n - x)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)

def mcnemar(b, c):
    return pmcm(min(b, c), b + c)

def boot_ci(d, n=20000, seed=7):
    random.seed(seed)
    means = sorted(sum(random.choice(d) for _ in d) / len(d) for _ in range(n))
    return means[int(n * 0.025)], means[int(n * 0.975)]

def power_mcnemar(m, theta):
    """exact two-sided 0.05 level; m discordant pairs; P(full correct | discordant)=theta"""
    pw = 0.0
    for x in range(m + 1):
        p = math.comb(m, x) * theta ** x * (1 - theta) ** (m - x)
        if p < 1e-12:
            continue
        if pmcm(x, m) < 0.05:
            pw += p
    return pw

full, abl, bare = arm_stats('full'), arm_stats('ablated'), arm_stats('bare')

# ---- paired stats: task-pass pairs ----
pairs = []
for pi in (0, 1):
    fp, ap = full['passes'][pi], abl['passes'][pi]
    for t in TASKS:
        pairs.append((t, fp[t], ap[t]))
n_pairs = len(pairs)

def discordant(key):
    b = sum(1 for _, f, a in pairs if not f[key] and a[key])   # ablated better
    c = sum(1 for _, f, a in pairs if f[key] and not a[key])   # full better
    return b, c

res = {'n_tasks': NT, 'n_pairs': n_pairs}
for name, key in (('ts', 'ts2'), ('tsa', 'tsa')):
    b, c = discordant(key)
    res[name] = {'b_abl_better': b, 'c_full_better': c,
                 'p_mcnemar': round(mcnemar(b, c), 4),
                 'rate_full': round(sum(bool(f[key]) for _, f, _ in pairs) / n_pairs, 4),
                 'rate_abl': round(sum(bool(a[key]) for _, _, a in pairs) / n_pairs, 4)}
d_af1 = [f['af1'] - a['af1'] for _, f, a in pairs]
lo, hi = boot_ci(d_af1)
res['af1_diff'] = {'mean': round(statistics.mean(d_af1), 4), 'ci95': [round(lo, 4), round(hi, 4)]}

# paired rate-difference CIs (full - ablated), bootstrap over task-pass pairs
for name, key in (('ts', 'ts2'), ('tsa', 'tsa')):
    dd = [int(bool(f[key])) - int(bool(a[key])) for _, f, a in pairs]
    lo, hi = boot_ci(dd)
    res[name + '_rate_diff'] = {'mean': round(statistics.mean(dd), 4),
                                'ci95': [round(lo, 4), round(hi, 4)]}

# ---- power at observed TSA discordance ----
b, c = discordant('tsa')
m = b + c
pw = {}
for th in (0.55, 0.60, 0.65, 0.70):
    pw[f'{th:.2f}'] = round(power_mcnemar(m, th), 3)
# observed theta
theta_obs = c / m if m else None
res['power'] = {'discordant_pairs': m, 'discordance_rate': round(m / n_pairs, 4),
                'theta_obs': round(theta_obs, 3) if theta_obs else None,
                'power_by_theta': pw,
                'equiv_delta_tsa': {f'{th:.2f}': round((m / n_pairs) * (2 * th - 1), 4)
                                    for th in (0.60, 0.65, 0.70)}}
# minimum theta for 0.8 power at current m
th_need = None
for i in range(500, 900):
    th = i / 1000
    if power_mcnemar(m, th) >= 0.8:
        th_need = th
        break
res['power']['theta_for_80power'] = th_need

# ---- arm summary table values (medians across the 2 passes) ----
def med(x):
    return statistics.median(x)
res['arms'] = {name: {'ts': round(med(a['ts']), 4), 'tsa': round(med(a['tsa']), 4),
                      'af1': round(med(a['af1']), 3), 'e2e_med_ms': int(med(a['e2e_med'])),
                      'cls': a['cls']}
               for name, a in (('full', full), ('ablated', abl), ('bare', bare))}

# ---- latency pool: canonical pass = full p1 ----
p1 = full['passes'][0]
mss = sorted(m['ms'] for t in TASKS for m in p1[t]['trace'] if m['ms'] > 0)
res['latency_full_p1'] = {'calls': len(mss),
                          'p50': mss[len(mss) // 2],
                          'p95': mss[int(len(mss) * 0.95) - 1],
                          'max': mss[-1],
                          'sum_s': round(sum(mss) / 1000, 1)}
e2e_full = sorted(p1[t]['e2e_ms'] for t in TASKS)
res['latency_full_p1']['e2e_p95'] = e2e_full[int(len(e2e_full) * 0.95) - 1]
a1 = abl['passes'][0]
amss = sorted(m['ms'] for t in TASKS for m in a1[t]['trace'] if m['ms'] > 0)
res['latency_abl_p1'] = {'calls': len(amss), 'p50': amss[len(amss) // 2]}

# ---- qualitative scans ----
miss = Counter()
for t in TASKS:
    r = p1[t]
    if not r['tsa']:
        miss[(TASKS[t]['gold_tool'], r['first_tool'] or 'NONE')] += 1
res['miss_pairs_top'] = [[list(k), v] for k, v in miss.most_common(12)]
res['n_miss_p1'] = sum(miss.values())

ZERO = ('"total": 0', '"total":0', '未找到', '无记录', '无数据', '没有查询到', '未查询到', '"results": []')
att = rec = 0
att_tasks = []
for t in TASKS:
    tr = p1[t]['trace']
    zi = [i for i, m in enumerate(tr) if any(z in m.get('obs', '') for z in ZERO)]
    if zi and max(zi) < len(tr) - 1:
        att += 1
        rec += bool(p1[t]['ts2'])
        att_tasks.append(t)
res['r1_reattempt'] = {'events': att, 'recovered': rec, 'tasks_sample': att_tasks[:10]}

TRUNC = ('page 1 of', '第1页', '共', '页', 'truncat', '分页', 'of ')
decl = sum(1 for t in TASKS
           if any(x in p1[t]['final'].lower() for x in ('page 1 of', '第1页', 'truncated', '截断'))
           and p1[t]['calls'] >= 1)
res['declared_truncation'] = decl

import re as _re

def ledger_specific_tokens(t):
    """tokens present in the frozen gold payload but absent from the question text:
    only a system that actually consulted the ledger could utter them."""
    q = t['query']
    ref = t.get('_ref', '')
    cands = set(_re.findall(r'(?:INFO|HD)_\d+', ref))
    cands |= set(_re.findall(r'\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?', ref))
    cands |= set(_re.findall(r'[a-z0-9][a-z0-9.-]+\.(?:cn|com|net|org|edu|test)\b', ref))
    cands |= {n for n in _re.findall(r'"(?:部门|单位|name|department|title)":\s*"([^"]{4,})"', ref)}
    cands |= set(_re.findall(r'"total":\s*(\d{2,})', ref))
    return {c for c in cands if c and c not in q}

bp = bare['passes'][0]
bare_ok = [t for t in TASKS if bp[t]['ts2']]
grounded, no_disc = [], []
for t in bare_ok:
    lt = ledger_specific_tokens(TASKS[t])
    ans = bp[t]['final'] or ''
    if not lt:
        no_disc.append(t)
    elif any(c in ans for c in lt):
        grounded.append(t)
res['bare_success'] = {'n': len(bare_ok),
                       'with_ledger_fact': len(grounded), 'grounded_tasks': grounded[:15],
                       'no_discriminating_tokens': len(no_disc),
                       'artifact_rate': round(1 - len(grounded) / len(bare_ok), 4) if bare_ok else None}

wr_int = sum(1 for t in TASKS for m in p1[t]['trace'] if 'simulated' in m.get('obs', '') and '"simulated": true' in m.get('obs', ''))
res['write_intercepts_p1'] = wr_int

stab = {}
for name, a in (('full', full), ('ablated', abl), ('bare', bare)):
    ch = [t for t in TASKS if bool(a['passes'][0][t]['ts2']) != bool(a['passes'][1][t]['ts2'])]
    stab[name] = len(ch)
    if ch:
        stab[name + '_tasks'] = ch[:15]
res['pass_stability'] = stab

calls = [p1[t]['calls'] for t in TASKS]
res['calls_full_p1'] = {'total': sum(calls), 'median': med(calls),
                        'six_step_cap': sum(1 for c in calls if c >= 6)}
print(json.dumps(res, ensure_ascii=False, indent=1, default=str))
