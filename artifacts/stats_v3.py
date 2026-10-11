#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3 re-analysis for the major-revision response (runs offline on released traces).

Adds, on top of stats_v2.py (whose scoring overlay is reused verbatim):
  1) Formal GROUNDED-SUCCESS metric for the tool-less arm (reviewer M7):
     a success is grounded iff the answer contains >=1 ledger-specific token that
     is also NON-DERIVABLE from the question text (bounded morphological
     completion rule, defined in derivable()).
  2) Task-CLUSTERED inference (M5): pass values aggregated per task (both-pass
     indicator + mean), McNemar on aggregated indicators, and a cluster
     bootstrap (resample tasks, keep both passes) for the paired deltas.
  3) Path-tolerant tool selection TSA+ and gold-visit arg-F1 AF1* (M6):
     check-before-write and department-name resolution before a departmental
     report tool are accepted when the gold tool is subsequently visited.
  4) Per-class task-level success with Wilson 95% CIs (m7).
  5) Operational metrics from traces (M10/m8): timeout/error-bearing calls,
     consecutive identical-arg retries, six-step cap incidence and failure
     rate among capped tasks, per-task call and server-time budget.
  6) Failure morphologies (m9) and drift overlap (M13).
Outputs v3_stats.json. No production calls.
"""
import json, math, random, statistics
from collections import defaultdict, Counter
import stats_v2 as S  # reuses overlay, loaders, EXCLUDE, verdict logic

TASKS, NT = S.TASKS, S.NT
CLSm = lambda tid: S.CLS(tid)

# ---------------- 1) formal grounded success ----------------
def derivable(tok, q):
    """Token is derivable from the question if the question already contains
    almost all of it: ASCII token (>=6 chars) appears as-is; or a >=3-char
    contiguous fragment of the question is a substring of the token and the
    token adds at most 2 characters (bounded morphological completion; e.g.
    a question that quotes a 4-char fragment of a 5-char canonical name)."""
    if tok in q:
        return True
    tok_s = tok.strip()
    if tok_s.isascii():
        return False  # ASCII ids/addresses must match exactly to count as seen
    n = len(tok_s)
    for i in range(n):
        for j in range(i + 3, n + 1):
            frag = tok_s[i:j]
            if n - len(frag) <= 2 and len(frag) >= 3 and frag in q:
                return True
    return False

def grounded_audit(passes):
    out = {}
    for pi, p in enumerate(passes, 1):
        ok = [t for t in TASKS if p[t]['ts2']]
        strict, loose, nodisc, deriv = [], [], [], []
        for t in ok:
            lt = S.ledger_specific_tokens(TASKS[t])
            ans = p[t]['final'] or ''
            hit = [c for c in lt if c in ans]
            if not lt:
                nodisc.append(t)
            elif not hit:
                pass
            else:
                loose.append(t)
                if any(not derivable(c, TASKS[t]['query']) for c in hit):
                    strict.append(t)
                else:
                    deriv.append(t)
        out[f'pass{pi}'] = {'token_match_successes': len(ok),
                            'no_discriminating_tokens': len(nodisc),
                            'loose_groundled': len(loose), 'loose_tasks': loose[:10],
                            'derivable_only': deriv,
                            'strict_groundled': len(strict), 'strict_tasks': strict}
    return out

# ---------------- 2) task-level aggregation + clustered inference ----------------
def task_ind(arm):
    """returns {tid: {'ts_both','ts_any','tsa_both','tsa_any','tsa+_both','tsa+_any',
    'ts_mean','tsa_mean','af1_mean','af1s_mean'}}"""
    ps = arm['passes']
    o = {}
    for t in TASKS:
        r1, r2 = ps[0][t], ps[1][t]
        def both(k): return bool(r1[k]) and bool(r2[k])
        def anyf(k): return bool(r1[k]) or bool(r2[k])
        o[t] = {
            'ts_both': both('ts2'), 'ts_any': anyf('ts2'),
            'tsa_both': both('tsa'), 'tsa_any': anyf('tsa'),
            'tsap_both': both('tsap'), 'tsap_any': anyf('tsap'),
            'ts_mean': (int(bool(r1['ts2'])) + int(bool(r2['ts2']))) / 2,
            'tsa_mean': (int(bool(r1['tsa'])) + int(bool(r2['tsa']))) / 2,
            'tsap_mean': (int(bool(r1['tsap'])) + int(bool(r2['tsap']))) / 2,
            'af1_mean': (r1['af1'] + r2['af1']) / 2,
            'af1s_mean': (r1['af1s'] + r2['af1s']) / 2,
        }
    return o

# ---------------- 3) TSA+ / AF1* enrichment of loaded passes ----------------
DEPT_REPORT = {'get_department_statistics_report', 'get_examine_report'}
WRITE_Q = {'add_black_ip': 'query_black_ips', 'add_black_dns': 'query_black_dns'}

def enrich(arm):
    for p in arm['passes']:
        for t, r in p.items():
            task = TASKS[t]
            gold = task['gold_tool']
            seq = [m['tool'] for m in r['trace']]
            tsap = bool(r['tsa'])
            if not tsap and seq:
                if gold in WRITE_Q and seq[0] == WRITE_Q[gold] and gold in seq:
                    tsap = True                      # check-before-write path
                elif gold in DEPT_REPORT and seq[0] == 'query_departments' and gold in seq:
                    tsap = True                      # name-resolution path
            r['tsap'] = tsap
            # AF1*: best gold-slot F1 over all visits to the gold tool
            gargs = task.get('gold_args', {})
            best = 0.0
            for m in r['trace']:
                if m['tool'] != gold or not gargs:
                    continue
                hit = sum(1 for k, v in gargs.items()
                          if str(m['args'].get(k, '')).strip().lower()
                          == str(v).strip().lower())
                best = max(best, hit / len(gargs))
            r['af1s'] = best if gargs else (1.0 if r['tsa'] else 0.0)

full, abl, bare = S.full, S.abl, S.bare
for a in (full, abl, bare):
    enrich(a)

TF, TA, TB = task_ind(full), task_ind(abl), task_ind(bare)

res = {'n_tasks': NT}

# ---------------- exact McNemar (from stats_v2) ----------------
pmcm, mcnemar = S.pmcm, S.mcnemar

def mcn_ind(key):
    b = sum(1 for t in TASKS if not TF[t][key] and TA[t][key])
    c = sum(1 for t in TASKS if TF[t][key] and not TA[t][key])
    return b, c, (mcnemar(b, c) if b + c else 1.0)

res['tasklevel_mcnemar'] = {k: dict(zip(('b_abl_better', 'c_full_better', 'p'), mcn_ind(k)))
                            for k in ('ts_both', 'ts_any', 'tsa_both', 'tsap_both')}

# pass-level McNemar for reference (identical to v2 for ts/tsa; new for tsap)
def mcn_pass(key):
    b = c = 0
    for pi in (0, 1):
        fp, ap = full['passes'][pi], abl['passes'][pi]
        for t in TASKS:
            if not fp[t][key] and ap[t][key]: b += 1
            elif fp[t][key] and not ap[t][key]: c += 1
    return b, c, mcnemar(b, c)
res['passlevel_mcnemar'] = {k: dict(zip(('b', 'c', 'p'), mcn_pass(k)))
                            for k in ('ts2', 'tsa', 'tsap')}

# ---------------- cluster bootstrap (tasks as clusters) ----------------
def cluster_boot(key, n=20000, seed=7):
    ids = list(TASKS)
    random.seed(seed)
    means = []
    for _ in range(n):
        s = 0.0
        for _ in ids:
            t = random.choice(ids)
            s += TF[t][key] - TA[t][key]
        means.append(s / len(ids))
    means.sort()
    d = sum(TF[t][key] - TA[t][key] for t in TASKS) / NT
    return d, means[int(n * 0.025)], means[int(n * 0.975)]

res['cluster_boot'] = {}
for k in ('ts_mean', 'tsa_mean', 'tsap_mean', 'af1_mean', 'af1s_mean'):
    d, lo, hi = cluster_boot(k)
    res['cluster_boot'][k] = {'delta': round(d, 4), 'ci95': [round(lo, 4), round(hi, 4)]}

# task-level discordance-based MDE (80% power, exact)
pw = S.power_mcnemar
b, c, _ = mcn_ind('ts_both')
m = b + c
th_need = next((i / 1000 for i in range(500, 901) if pw(m, i / 1000) >= 0.8), None)
res['tasklevel_mde'] = {'ts_both_discordant': m,
                        'theta_for_80pct_power': th_need,
                        'MDE_pp': round((m / NT) * (2 * th_need - 1) * 100, 2) if th_need else None}

# ---------------- per-class Wilson CIs (task level, both-pass) ----------------
def wilson(k, n):
    if n == 0:
        return (0, 0)
    z = 1.96
    ph = k / n
    d = 1 + z * z / n
    ctr = (ph + z * z / (2 * n)) / d
    hw = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (round(max(0, ctr - hw) * 100, 1), round(min(1, ctr + hw) * 100, 1))

cls = defaultdict(lambda: [0, 0, 0, 0])   # n, fullK, ablK, (bare any)
for t in TASKS:
    i = CLSm(t)
    cls[i][0] += 1
    cls[i][1] += int(TF[t]['ts_both'])
    cls[i][2] += int(TA[t]['ts_both'])
res['per_class'] = {k: {'n': v[0],
                        'full': round(100 * v[1] / v[0], 1), 'full_ci95': wilson(v[1], v[0]),
                        'ablated': round(100 * v[2] / v[0], 1), 'ablated_ci95': wilson(v[2], v[0])}
                    for k, v in sorted(cls.items())}

# ---------------- operational metrics (m8 / M10) ----------------
ERRM = ('ERROR', '超时', 'timeout', 'timed out', '"error"')
def ops(arm):
    p1 = arm['passes'][0]
    calls = err = retry = 0
    for t in TASKS:
        tr = p1[t]['trace']
        calls += len(tr)
        err += sum(1 for m in tr if any(e in (m.get('obs') or '')[:220] for e in ERRM))
        retry += sum(1 for a, b in zip(tr, tr[1:])
                     if a['tool'] == b['tool'] and a['args'] == b['args'])
    capped = [t for t in TASKS if p1[t]['calls'] >= 6]
    capped_fail = [t for t in capped if not p1[t]['ts2']]
    ms_pool = sorted(m['ms'] for t in TASKS for m in p1[t]['trace'] if m['ms'] > 0)
    e2e = sorted(p1[t]['e2e_ms'] for t in TASKS)
    return {'tool_calls': calls, 'calls_median': statistics.median([p1[t]['calls'] for t in TASKS]),
            'err_calls': err, 'err_rate': round(err / calls, 4),
            'retry_calls': retry,
            'capped_tasks': len(capped), 'capped_fail': len(capped_fail), 'capped_fail_tasks': capped_fail[:12],
            'srv_ms_sum_s': round(sum(ms_pool) / 1000, 1),
            'srv_p50': ms_pool[len(ms_pool) // 2], 'srv_p95': ms_pool[int(len(ms_pool) * 0.95) - 1],
            'srv_max': ms_pool[-1],
            'e2e_med': e2e[len(e2e) // 2], 'e2e_p95': e2e[int(len(e2e) * 0.95) - 1],
            'srv_share_pct': round(100 * sum(ms_pool) / sum(e2e), 1)}
res['ops'] = {'full_p1': ops(full), 'ablated_p1': ops(abl)}

# model-turn estimate: chat calls = tool calls + final turn (cap 6 iterations)
p1 = full['passes'][0]
turns = sum(min(p1[t]['calls'] + 1, 6) if p1[t]['calls'] >= 6 else p1[t]['calls'] + 1 for t in TASKS)
res['model_turns_full_p1_est'] = turns

# ---------------- failure morphologies (m9) + drift overlap (M13) ----------------
refb = {t['id']: t for t in json.load(open('tasks_v2_refrozen.json', encoding='utf-8'))}
changed = sorted(t for t in TASKS if TASKS[t].get('_ref', '') != refb[t].get('_ref', ''))
res['drift_changed_tasks'] = changed

def failures(arm):
    out = []
    for t in TASKS:
        r1, r2 = arm['passes'][0][t], arm['passes'][1][t]
        if r1['ts2'] and r2['ts2']:
            continue
        tr = r1['trace']
        cause = []
        if any(any(e in (m.get('obs') or '')[:220] for e in ERRM) for m in tr): cause.append('log-store error/timeout')
        if not r1['tsa'] and not r2['tsa']: cause.append('first-hop selection miss')
        if TASKS[t]['gold_tool'] == 'search_assets' and TASKS[t]['gold_args'].get('field') == 'ip':
            cause.append('hosting-only relay at shared address')
        if any('simulated' in (m.get('obs') or '') for m in tr): cause.append('write task')
        if r1['calls'] >= 6: cause.append('six-step cap')
        out.append({'id': t, 'class': CLSm(t), 'gold': TASKS[t]['gold_tool'],
                    'first': (r1['first_tool'] or 'NONE'),
                    'fail_p1': not r1['ts2'], 'fail_p2': not r2['ts2'],
                    'cause': cause or ['content mis-relay'], 'drifted': t in changed})
    return out
res['failures_full'] = failures(full)
res['failures_ablated'] = failures(abl)

# ---------------- grounded audit (strict) ----------------
res['grounded_bare'] = grounded_audit(bare['passes'])

# ---------------- TSA+/AF1* arm summaries (pass medians) ----------------
def arm_sum(arm):
    ps = arm['passes']
    return {'tsa': round(100 * statistics.mean([sum(bool(p[t]['tsa']) for t in TASKS) / NT for p in ps]), 1),
            'tsap': round(100 * statistics.mean([sum(bool(p[t]['tsap']) for t in TASKS) / NT for p in ps]), 1),
            'af1': round(statistics.mean([statistics.mean([p[t]['af1'] for t in TASKS]) for p in ps]), 3),
            'af1s': round(statistics.mean([statistics.mean([p[t]['af1s'] for t in TASKS]) for p in ps]), 3)}
res['arm_tsa'] = {'full': arm_sum(full), 'ablated': arm_sum(abl)}
res['tsap_miss_full_p1'] = [t for t in TASKS if not full['passes'][0][t]['tsap']]
res['tsap_miss_abl_p1'] = [t for t in TASKS if not abl['passes'][0][t]['tsap']]

# arm headline (task-level both-pass TS)
res['headline_tasklevel'] = {'full': round(100 * sum(TF[t]['ts_both'] for t in TASKS) / NT, 1),
                             'ablated': round(100 * sum(TA[t]['ts_both'] for t in TASKS) / NT, 1),
                             'full_any': round(100 * sum(TF[t]['ts_any'] for t in TASKS) / NT, 1),
                             'ablated_any': round(100 * sum(TA[t]['ts_any'] for t in TASKS) / NT, 1)}

json.dump(res, open('v3_stats.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1, default=str)
print(json.dumps({k: res[k] for k in
                  ('headline_tasklevel', 'tasklevel_mcnemar', 'cluster_boot', 'arm_tsa',
                   'tasklevel_mde', 'grounded_bare')}, ensure_ascii=False, indent=1, default=str))
print('--- per_class ---'); print(json.dumps(res['per_class'], ensure_ascii=False))
print('--- ops ---'); print(json.dumps(res['ops'], ensure_ascii=False))
print('--- fails ---'); print(json.dumps(res['failures_full'], ensure_ascii=False, indent=1))
print(json.dumps(res['failures_ablated'], ensure_ascii=False, indent=1))
print('drift changed:', res['drift_changed_tasks'])
