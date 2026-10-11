#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-score stored H runs with the current h_runner.score (lowercase-matching
bug fix). Only the `ts` and `det` fields are rewritten; traces and final
answers are untouched. Symmetric across all arms/passes."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Mcp
import h_runner

tasks = {t['id']: t for t in json.load(open('tasks_h.json', encoding='utf-8'))}
mcp = Mcp(os.environ['MCP_URL'], os.environ['MCP_TOKEN'])
mcp.init()
h_runner.TOOL_NAMES = [t['name'] for t in mcp.tools_list()]

files = sys.argv[1:] or ['h_full_p1.jsonl', 'h_full_p2.jsonl',
                         'h_abl_p1.jsonl', 'h_abl_p2.jsonl']
for fp in files:
    lines = [json.loads(l) for l in open(fp, encoding='utf-8')]
    n_ok = flips = 0
    for r in lines:
        ok, det = h_runner.score(tasks[r['task']], r)
        if ok != r['ts']:
            print(f'  FLIP {r["task"]}: {r["ts"]} -> {ok}')
            flips += 1
        r['ts'], r['det'] = ok, det
        n_ok += int(ok)
    with open(fp, 'w', encoding='utf-8') as fh:
        for r in lines:
            fh.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(f'{fp}: {len(lines)} tasks, {n_ok} OK ({100*n_ok/len(lines):.0f}%), {flips} flips')
