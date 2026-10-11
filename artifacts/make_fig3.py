#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build figures/fig3_trajectory.svg from a full-arm JSONL trace (default task X1).
Sequence-style layout: operator query -> agent; per step a solid request arrow
(right to left, args label above) and a dashed response arrow (left to right,
observation digest above, latency at right margin). English-only: CJK is
stripped from digests; identifiers masked as well."""
import json, re, sys

TASK = sys.argv[1] if len(sys.argv) > 1 else 'X1'
runs = [json.loads(l) for l in open('results_full.jsonl', encoding='utf-8')]
r = next(x for x in runs if x['task'] == TASK)
qtext = next(x['query'] for x in json.load(open('tasks_v1.json', encoding='utf-8')) if x['id'] == TASK)

def ascii_only(s):
    s = re.sub(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+', '[zh]', s)
    return re.sub(r' +', ' ', s).strip()

def mask_ips(s):
    # host addresses are masked to two octets (paper's stated masking policy);
    # CIDR prefixes are ledger-level facts and stay visible
    return re.sub(r'\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b(?![/\d])', r'\1.\2.*.*', s)

def sanitize(s):
    # paper masking policy for figures: asset identifiers reduce to their class
    # prefix, campus domains to a masked form; CIDR prefixes stay ledger-level
    s = re.sub(r'([A-Z][A-Z0-9]*[A-Z])_\d{4,}', r'\1_*****', s)
    s = re.sub(r'\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.***\.edu\.cn\b',
               lambda m: m.group(0)[0] + '***.edu.cn', s)
    return s

def esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def digest(tool, obs):
    o = ascii_only(obs or '')
    m = re.search(r'"total":\s*(\d+)', o)
    if m:
        d = 'total=' + m.group(1)
    else:
        m2 = re.search(r'([A-Z]{2,4}_\d+)', o)
        d = m2.group(1) if m2 else o[:60]
    return mask_ips(f'{tool}  ->  {d}')

q = mask_ips(ascii_only(qtext))
final = re.sub(r'\s+', ' ', mask_ips(ascii_only(r['final'] or '')))
final = re.sub(r'\*\*', '', final)
final = re.sub(r'\|\s*-{2,}\s*(?:\|\s*-{2,}\s*)*\|', ' ', final)   # md table rules
final = re.sub(r'\s*\|\s*', '  ·  ', final)                        # md pipes -> dots
final = re.sub(r'\s{2,}', ' ', final).strip()
if len(final) > 430:
    final = final[:430].rsplit(' ', 1)[0] + ' ...'
flines, cur = [], ''
for w in final.split(' '):
    if len(cur) + len(w) + 1 > 104:
        flines.append(cur); cur = w
    else:
        cur = (cur + ' ' + w).strip()
if cur: flines.append(cur)
flines = flines[:4]

steps = r['trace']
LX, RX = 190, 700            # lifeline x positions
PITCH = 50                   # request + response pair height
y0 = 126                     # first request arrow
y_query = 96
ybot = y0 + PITCH * (len(steps) - 1) + 22 + 14   # after last response arrow
fb = 22 * len(flines) + 22
H = ybot + 12 + fb + 30

parts = [
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 {H}" font-family="Helvetica, Arial, sans-serif">',
    '<defs>'
    '<marker id="aL" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="#333"/></marker>'
    '<marker id="aR" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="#7a9cbd"/></marker>'
    '</defs>',
    f'<text x="20" y="30" font-size="14" font-weight="bold">Task {TASK} - richest full-arm trajectory ({len(steps)} tool calls, end-to-end {r["e2e_ms"]:,} ms)</text>',
    # lifelines
    f'<line x1="{LX}" y1="64" x2="{LX}" y2="{ybot}" stroke="#bbb" stroke-dasharray="4 4"/>',
    f'<line x1="{RX}" y1="64" x2="{RX}" y2="{ybot}" stroke="#bbb" stroke-dasharray="4 4"/>',
    f'<rect x="{LX-62}" y="46" width="124" height="20" rx="4" fill="#eef4fa" stroke="#9db8d2"/>'
    f'<text x="{LX}" y="60" text-anchor="middle" font-size="11.5" font-weight="bold">MCP tool layer</text>',
    f'<rect x="{RX-62}" y="46" width="124" height="20" rx="4" fill="#eef4fa" stroke="#9db8d2"/>'
    f'<text x="{RX}" y="60" text-anchor="middle" font-size="11.5" font-weight="bold">agent runtime</text>',
    # operator query -> agent
    '<text x="20" y="82" font-size="10.5" font-weight="bold" fill="#444">security operator</text>',
    '<text x="20" y="95" font-size="9.5" fill="#888">(user query)</text>',
    f'<line x1="118" y1="{y_query}" x2="{RX-14}" y2="{y_query}" stroke="#555" stroke-width="1.2" stroke-dasharray="2 3" marker-end="url(#aL)"/>',
    f'<text x="126" y="{y_query-6}" font-size="10.5" fill="#333">{esc(q[:118])}</text>',
]

y = y0
for i, m in enumerate(steps, 1):
    args = mask_ips(ascii_only(json.dumps(m['args'], ensure_ascii=False)))[:70]
    dig = digest(m['tool'], m.get('obs', ''))
    ms = m['ms']
    # request arrow (agent -> tool) with args label above
    parts.append(f'<text x="{LX+12}" y="{y-6}" font-size="10" fill="#555">args: {esc(args)}</text>')
    parts.append(f'<line x1="{RX-12}" y1="{y}" x2="{LX+2}" y2="{y}" stroke="#333" stroke-width="1.4" marker-end="url(#aL)"/>')
    parts.append(f'<circle cx="{RX}" cy="{y}" r="10.5" fill="#2c5f8a"/>'
                 f'<text x="{RX}" y="{y+3.5}" text-anchor="middle" fill="#fff" font-size="10.5">{i}</text>')
    # response arrow (tool -> agent) with digest label above, latency right margin
    yr = y + 23
    parts.append(f'<text x="{LX+12}" y="{yr-5}" font-size="10.5" font-weight="bold" fill="#1f4e79">{esc(dig)}</text>')
    parts.append(f'<text x="904" y="{yr-5}" text-anchor="end" font-size="9.5" fill="#888">{ms} ms</text>')
    parts.append(f'<line x1="{LX+2}" y1="{yr}" x2="{RX-12}" y2="{yr}" stroke="#7a9cbd" stroke-width="1.2" stroke-dasharray="5 3" marker-end="url(#aR)"/>')
    y += PITCH

# final answer box
parts.append(f'<rect x="24" y="{ybot+12}" width="872" height="{fb}" rx="6" fill="#eef4fa" stroke="#9db8d2"/>')
parts.append(f'<text x="36" y="{ybot+30}" font-size="10.5" font-weight="bold" fill="#1f4e79">final answer (relays only fields present in tool observations, guardrail R3):</text>')
for k, ln in enumerate(flines):
    parts.append(f'<text x="36" y="{ybot+50+22*k}" font-size="10.5">{esc(ln)}</text>')
parts.append(f'<text x="24" y="{H-10}" font-size="10" fill="#666">Solid arrows: tool requests with call arguments. Dashed arrows: tool observations fed back to the agent; digests are ASCII extracts of the JSON payload.</text>')
parts.append('</svg>')

open('../figures/fig3_trajectory.svg', 'w', encoding='utf-8').write(sanitize('\n'.join(parts)))
print('wrote ../figures/fig3_trajectory.svg task=', TASK, 'steps=', len(steps), 'H=', H)
