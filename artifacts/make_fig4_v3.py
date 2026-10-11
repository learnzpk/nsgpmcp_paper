#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fig. 4 (v3, major revision): numbers transcribed from v3_stats.json /
tasks_h summary (see comments). Three panels:
 (a) task-level success (success in BOTH passes) by class, Wilson 95% CIs;
 (b) tool-less arm: token-match "successes" vs strict grounded successes;
 (c) paired full - ablated deltas, task-clustered bootstrap 95% CIs.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BLUE, GREY, HBAR, RED = '#2c5f8a', '#9aa7b4', '#c9d6e4', '#b2544f'
plt.rcParams.update({'font.size': 8.6, 'axes.linewidth': .8,
                     'xtick.major.width': .8, 'ytick.major.width': .8,
                     'axes.titlesize': 9.2, 'axes.titleweight': 'bold'})

fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(9.9, 3.15))
fig.subplots_adjust(left=.055, right=.985, top=.86, bottom=.16, wspace=.30)

# ---------------- (a) per-class task-level success with Wilson CIs ----------------
# from v3_stats.json per_class (both-pass criterion, n shown under class)
cls = ['asset\n(92)', 'log\n(51)', 'disposition\n(38)', 'org\n(24)', 'stat\n(23)', 'project\n(10)', 'cross\n(15)']
full_k = [100.0, 94.1, 97.4, 100.0, 100.0, 100.0, 86.7]
full_ci = [[96.0, 100], [84.1, 98.0], [86.5, 99.5], [86.2, 100], [85.7, 100], [72.2, 100], [62.1, 96.3]]
abl_k  = [97.8, 94.1, 100.0, 100.0, 100.0, 100.0, 80.0]
abl_ci = [[92.4, 99.4], [84.1, 98.0], [90.8, 100], [86.2, 100], [85.7, 100], [72.2, 100], [54.8, 93.0]]
x = np.arange(len(cls)); w = .36
def err(k, ci):
    lo = [a - c[0] for a, c in zip(k, ci)]
    hi = [c[1] - a for a, c in zip(k, ci)]
    return [lo, hi]
ax1.bar(x - w/2, full_k, w, color=BLUE, zorder=3, label='full agent')
ax1.bar(x + w/2, abl_k, w, color=GREY, zorder=3, label='ablated')
ax1.errorbar(x - w/2, full_k, yerr=err(full_k, full_ci), fmt='none', ecolor='#1d3f5c', elinewidth=.9, capsize=2, zorder=4)
ax1.errorbar(x + w/2, abl_k, yerr=err(abl_k, abl_ci), fmt='none', ecolor='#5c6672', elinewidth=.9, capsize=2, zorder=4)
ax1.set_xticks(x); ax1.set_xticklabels(cls, fontsize=7.2)
ax1.set_ylim(55, 104); ax1.set_ylabel('success (both passes, %)')
ax1.set_title('(a) success by class (n in labels)')
ax1.grid(axis='y', color=HBAR, zorder=0)
ax1.legend(frameon=False, fontsize=7.6, loc='lower left')

# ---------------- (b) grounded success ----------------
# v3 grounded_bare: token-match 103/253 (41.3%) pass1, 106/253 (41.9%) pass2;
# strict grounded 0/253 both passes (O101 token derivable from question).
xb = np.arange(2)
ax2.bar(xb - .17, [41.3, 41.9], .32, color=GREY, zorder=3, label='token-match "success"')
ax2.bar(xb + .17, [0.0, 0.0], .32, color=RED, zorder=3, label='grounded success')
ax2.text(0.17, 1.2, '0/253', ha='center', fontsize=7.6, color=RED)
ax2.text(1.17, 1.2, '0/253', ha='center', fontsize=7.6, color=RED)
ax2.text(-0.17, 42.6, '103/253', ha='center', fontsize=7.2, color='#5c6672')
ax2.text(0.83, 43.2, '106/253', ha='center', fontsize=7.2, color='#5c6672')
ax2.set_xticks(xb); ax2.set_xticklabels(['pass 1', 'pass 2'])
ax2.set_ylim(0, 52); ax2.set_ylabel('% of 253 tasks')
ax2.set_title('(b) tool-less arm: echo vs grounded')
ax2.grid(axis='y', color=HBAR, zorder=0)
ax2.legend(frameon=False, fontsize=7.2, loc='upper center', bbox_to_anchor=(.5, .82))

# ---------------- (c) forest: task-clustered paired deltas ----------------
# v3 cluster_boot (20,000 task-cluster resamples, seed 7) + tasklevel McNemar
rows = [
    ('Task success (both pass)',   0.59, -0.79, 1.98, 'p = 0.75'),
    ('Tool selection (strict)',   -0.59, -1.78, 0.40, 'p = 1.00'),
    ('Tool selection (path-tol.)', 0.00, -0.99, 0.79, 'p = 1.00'),
    ('Arg. F1 (first call)',       0.10, -1.09, 1.28, ''),
    ('Arg. F1 (any gold visit)',   0.64, -0.49, 1.81, ''),
]
ys = np.arange(len(rows))[::-1]
for y, (lab, d, lo, hi, p) in zip(ys, rows):
    ax3.plot([lo, hi], [y, y], color='#3d4854', lw=1.1, zorder=3)
    ax3.plot([lo, lo], [y-.13, y+.13], color='#3d4854', lw=1.1, zorder=3)
    ax3.plot([hi, hi], [y-.13, y+.13], color='#3d4854', lw=1.1, zorder=3)
    ax3.plot(d, y, 'o', ms=4.6, color=BLUE, zorder=4)
    if p:
        ax3.text(hi + .16, y, p, va='center', fontsize=6.8, color='#5c6672')
ax3.axvline(0, color=RED, lw=.9, ls='--', zorder=2)
ax3.set_yticks(ys); ax3.set_yticklabels([r[0] for r in rows], fontsize=7.4)
ax3.set_xlim(-3.0, 3.4); ax3.set_xlabel('full − ablated (percentage points)')
ax3.set_title('(c) paired deltas, task-clustered 95% CI')
ax3.grid(axis='x', color=HBAR, zorder=0)

fig.savefig('../figures/fig4_results_preview.png', dpi=200, facecolor='white')
print('fig4 v3 saved')
