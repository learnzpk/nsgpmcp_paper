#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate suite v2 (target ~280 tasks) from live production ledgers.
Modes: --fetch (entity pool -> entities.json) | --gen (tasks_v2.json) | --validate
Gold references are frozen afterwards via: harness.py --mode freeze --tasks tasks_v2.json
Design rules:
  - required_all prefers stable ASCII tokens present in the frozen payload
    (ids, IPs, CIDRs, domains, years); proper names allowed (operators' payloads are Chinese).
  - required_any carries bilingual verdict tokens (zh+en) to avoid the v1 scorer blind spot.
  - negative tasks (not-on-campus, not-blocked, absent) get forbidden wrong-claims.
  - write tasks run in plan mode (harness intercepts); targets are TEST-NET or already-listed.
"""
import json, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Mcp

random.seed(20261011)
E = 'entities.json'
T2 = 'tasks_v2.json'

def mcp():
    m = Mcp(os.environ["MCP_URL"], os.environ["MCP_TOKEN"]); m.init(); return m

def jload(s):
    try: return json.loads(s)
    except Exception: return None

# ---------------- fetch ----------------
def fetch():
    m = mcp(); ent = {}
    # departments (page through)
    deps = []
    for p in (1, 2):
        d = jload(m.call('query_departments', {'page': str(p), 'page_size': '60'})) or {}
        rs = d.get('results') or d.get('单位列表') or (list(d.values())[0].get('results') if d and isinstance(list(d.values())[0], dict) else [])
        for r in rs or []:
            nm = r.get('name') or r.get('部门') or r.get('单位')
            if nm: deps.append(nm)
    ent['departments'] = sorted(set(deps))
    # assets per sampled departments
    assets = []
    for dep in random.sample(ent['departments'], min(26, len(ent['departments']))):
        for atype in ('information', 'hardware'):
            d = jload(m.call('query_department_assets', {'department': dep, 'asset_type': atype, 'page_size': '20'})) or {}
            block = d.get('results') if 'results' in d else (list(d.values())[0].get('results') if d and isinstance(list(d.values())[0], dict) else [])
            for r in block or []:
                if isinstance(r, dict) and (r.get('id') or '').count('_'):
                    assets.append({'id': r.get('id'), 'name': r.get('name', ''), 'department': r.get('department', dep),
                                   'ip': r.get('ip', ''), 'domain': r.get('domainname', '') or r.get('domain', ''),
                                   'type': atype, 'admin': r.get('administrator', ''), 'status': r.get('status', '')})
            time.sleep(0.05)
    ent['assets'] = assets
    # black ip entries
    dips, cidrs = [], []
    d = jload(m.call('query_black_ips', {'page_size': '100'})) or {}
    for r in (d.get('results') or []):
        v = r.get('ip') or ''
        if '/' in v: cidrs.append(v)
        elif v: dips.append(v)
    ent['black_ip_single'], ent['black_ip_cidr'] = dips, cidrs
    # black dns entries
    bdom = []
    d = jload(m.call('query_black_dns', {'page_size': '100'})) or {}
    for r in (d.get('results') or []):
        dm = r.get('domain') or r.get('域名') or ''
        if dm: bdom.append(dm)
    ent['black_dns'] = bdom
    # notices sample (for units+years)
    notices = []
    for yr in ('2024', '2025', '2026'):
        d = jload(m.call('query_event_notices', {'year': yr, 'page_size': '30'})) or {}
        for r in (d.get('results') or []):
            notices.append({'year': yr, 'department': r.get('department', ''), 'title': r.get('title', '')[:60],
                            'status': r.get('rectification_status', '') or r.get('整改状态', '')})
    ent['notices'] = notices
    # projects
    projs = []
    d = jload(m.call('search_projects', {'page_size': '40'})) or {}
    for r in (d.get('results') or []):
        projs.append({'id': r.get('id', ''), 'name': r.get('name', ''), 'supplier': r.get('supplier', ''),
                      'warranty': r.get('warranty_status', '') or r.get('维保状态', '')})
    ent['projects'] = projs
    # internal ip candidates from assets, verified via check_ip_internal
    ipool, ext = [], ['8.8.*.*', '1.1.*.*', '114.114.*.*', '223.5.*.*', '119.29.*.*',
                      '220.181.*.*', '39.156.*.*', '180.101.*.*', '123.125.*.*',
                      '140.205.*.*', '101.200.*.*', '47.92.*.*', '45.113.*.*',
                      '91.189.*.*', '151.101.*.*', '199.232.*.*', '208.80.*.*',
                      '20.205.*.*', '142.250.*.*', '13.107.*.*', '104.16.*.*',
                      '52.84.*.*', '17.57.*.*', '185.199.*.*']
    for a in assets:
        ip = (a['ip'] or '').split(',')[0].strip()
        if ip.count('.') == 3 and ip not in ipool: ipool.append(ip)
    ok_int = []
    for ip in random.sample(ipool, min(40, len(ipool))):
        o = m.call('check_ip_internal', {'ip': ip})
        if 'true' in o.lower() or '是' in o or ('前缀' in o and '未' not in o):
            ok_int.append(ip)
        if len(ok_int) >= 16: break
    ent['internal_ips'] = ok_int
    ok_ext = []
    for ip in ext:
        o = m.call('check_ip_internal', {'ip': ip})
        if 'true' not in o.lower() and '未' in o or 'false' in o.lower() or '不是' in o or '不属于' in o:
            ok_ext.append(ip)
    ent['external_ips'] = ok_ext[:16]
    # real covered ips: pick one host inside each of up to 10 CIDR entries, verify coverage
    cov = []
    for c in ent['black_ip_cidr'][:40]:
        try:
            base, bits = c.split('/'); bits = int(bits)
            if bits > 23: continue
            p = base.split('.'); host = f"{p[0]}.{p[1]}.{int(p[2])+7}.{int(p[3])+13}"
            o = m.call('query_black_ips', {'ip': host})
            if c in o: cov.append({'ip': host, 'cidr': c})
        except Exception: pass
        if len(cov) >= 12: break
    ent['covered'] = cov
    # uncovered public ips (verified absent & not covered)
    unc, cand = [], [f"198.{random.randint(51,51)}.{random.randint(10,250)}.{random.randint(10,250)}" for _ in range(10)] + \
                       [f"203.0.113.{random.randint(10,250)}" for _ in range(8)] + ['93.184.*.*','9.9.*.*','77.88.*.*','88.88.*.*','64.64.*.*','216.58.*.*','35.186.*.*','54.239.*.*']
    for ip in cand:
        o = m.call('query_black_ips', {'ip': ip})
        if ('total": 0' in o or 'total":0' in o or '未找到' in o or '无' in o) and '封锁' not in o:
            unc.append(ip)
        if len(unc) >= 14: break
    ent['uncovered_ips'] = unc
    # wireless: verify a window aggregate works; record field names of one record
    o = m.call('query_wireless_auth_logs', {'begin_time': '2026-10-04', 'end_time': '2026-10-10', 'page_size': '5'})
    ent['wifi_probe'] = o[:400]
    w = jload(o) or {}
    rs = w.get('results') or []
    ent['wifi_fields'] = sorted(rs[0].keys()) if rs and isinstance(rs[0], dict) else []
    ent['real_accounts'] = ['3240608029']
    # probe: asset IPs whose search_assets echo contains the asset id on page 1
    probed = 0
    for a in assets:
        ip = (a['ip'] or '').split(',')[0].strip()
        if a['id'].startswith('INFO') and ip.count('.') == 3:
            o2 = m.call('search_assets', {'keyword': ip, 'field': 'ip'})
            a['ip_ok'] = a['id'] in o2[:4000]   # same truncation as harness freeze _ref
            probed += 1
            time.sleep(0.03)
            if probed >= 80: break
    # probe: domains with real traffic in 2026-10-04..10 (web proxy + recursive DNS)
    cand_dom = list({x['domain'] for x in assets if x['domain']})[:24] + ['***.edu.cn']
    web_hit, dns_hit = [], []
    for dm in cand_dom:
        if len(web_hit) >= 8 and len(dns_hit) >= 5: break
        o2 = jload(m.call('query_web_access_logs', {'domain': dm, 'begin_time': '2026-10-04 00:00:00',
                                                    'end_time': '2026-10-10 23:59:59', 'page_size': '3'})) or {}
        if (o2.get('total') or 0) > 0: web_hit.append(dm)
        o3 = jload(m.call('query_dns_query_logs', {'domain': dm, 'begin_time': '2026-10-04', 'end_time': '2026-10-10'})) or {}
        if (o3.get('total') or 0) > 0: dns_hit.append(dm)
    ent['web_domains'], ent['dns_domains'] = web_hit[:8], dns_hit[:5]
    # departments exactly present in the annual assessment ledger (names can differ,
    # e.g. party-committee variants; the tool fuzzy-matches and may return another unit)
    exok = []
    for dep in random.sample(ent['departments'], 12):
        o2 = m.call('get_examine_report', {'department': dep})
        if dep in o2: exok.append(dep)
    ent['examine_depts'] = exok
    json.dump(ent, open(E, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('entities:', {k: (len(v) if isinstance(v, list) else 'str') for k, v in ent.items()})

# ---------------- generate ----------------
def gen():
    ent = json.load(open(E, encoding='utf-8'))
    tasks, n = [], 0
    def add(cls, tool, args, q_all, req, any_=None, forb=None, qzh=''):
        nonlocal n
        n += 1
        tid = f"{cls}{n if cls!='X' else n}"
        tasks.append({'id': tid, 'class': cls, 'query': q_all, 'query_zh': qzh,
                      'gold_tool': tool, 'gold_args': args,
                      'required_all': req, **({'required_any': any_} if any_ else {}),
                      **({'forbidden': forb} if forb else {})})
    info = [a for a in ent['assets'] if a['id'].startswith('INFO') and a['name']]
    hard = [a for a in ent['assets'] if a['id'].startswith('HD') and a['name']]
    pool = info[:60] + hard[:30]

    # ---- A: search_assets (24) ----
    for a in random.sample([x for x in info if x['domain']], min(8, len(info))):
        add('A', 'search_assets', {'keyword': a['domain']},
            f"Look up the information system by its domain {a['domain']}: report its asset ID and owning department.",
            [a['id'], a['department'] or a['domain']], qzh=f"查域名 {a['domain']} ***：编号、归属部门。")
    for a in random.sample(info, min(10, len(info))):
        kw = a['name'][:6]
        add('A', 'search_assets', {'keyword': kw},
            f"Find the campus information system whose name starts with “{kw}”: its ID, owner department and status.",
            [a['id']], any_=[a['department'] or 'department', 'department', '部门'],
            qzh=f"查找名称含“{kw}”的系统：编号、归属、状态。")
    ipok = [x for x in info if x['ip'] and x['ip'].count('.') == 3 and x.get('ip_ok')]
    for a in random.sample(ipok, min(6, len(ipok))):
        add('A', 'search_assets', {'keyword': a['ip'], 'field': 'ip'},
            f"Which information system is deployed at {a['ip']}? Report its ID and administrator.",
            [a['id']], any_=[a['admin'] or 'admin', 'administrator', '管理员'],
            qzh=f"{a['ip']} 上部署的是哪个系统？编号、管理员。")
    # detail (20)
    for a in random.sample(info, min(12, len(info))):
        add('A', 'get_asset_detail', {'asset_id': a['id'], 'asset_type': 'information'},
            f"Show the full ledger record of information asset {a['id']}: owning department, status and administrator.",
            [a['id'], a['department'] or '—'], any_=['状态', 'status', '上线', '管理员'],
            qzh=f"查看信息资产 {a['id']} 的完整台账：归属、状态、管理员。")
    for a in random.sample(hard, min(8, len(hard))):
        add('A', 'get_asset_detail', {'asset_id': a['id'], 'asset_type': 'hardware'},
            f"Show the hardware asset {a['id']}: what is it, where does it belong and who owns it?",
            [a['id']], any_=[a['department'] or 'department', 'department', '部门', '型号'],
            qzh=f"硬件资产 {a['id']} 是什么、归属、负责人？")
    # security profile (20)
    for a in random.sample(info, min(15, len(info))):
        add('A', 'get_asset_security', {'asset_id': a['id']},
            f"Pull the security profile of {a['id']}: any bulletin/remediation records and its external exposure setting.",
            [a['id']], any_=['通报', '整改', 'bulletin', 'remediation', '开放', 'exposure'],
            qzh=f"拉取 {a['id']} 的安全档案：通报整改记录、对外开放策略。")
    for a in random.sample(hard, min(5, len(hard))):
        add('A', 'get_asset_security', {'asset_id': a['id']},
            f"What does the security profile say about hardware {a['id']}?",
            [a['id']], any_=['通报', '整改', '记录', 'bulletin', '无'],
            qzh=f"硬件 {a['id']} 的安全档案怎么说？")
    # department assets (16)
    for dep in random.sample(ent['departments'], 10):
        at = random.choice(['information', 'hardware'])
        add('A', 'query_department_assets', {'department': dep, 'asset_type': at},
            f"Inventory the {at} assets owned by {dep}: how many in total and name a few.",
            [dep], any_=['total', '总数', 'INFO_', 'HD_', '共'],
            qzh=f"{dep} 的{('信息系统' if at=='information' else '硬件')}清单：共多少、列几个。")
    for dep in random.sample(ent['departments'], 6):
        add('A', 'query_department_assets', {'department': dep, 'asset_type': 'information', 'status': '上线'},
            f"List the ONLINE information systems of {dep}.",
            [dep], any_=['total', '总数', 'INFO_', '共', '上线'],
            qzh=f"{dep} 在线（上线）的信息系统清单。")
    # ip allocation (12)
    for ip in ent['internal_ips'][:12]:
        add('A', 'query_ip_allocation', {'query': ip},
            f"What does the IP allocation ledger say about {ip} (segment, hardware, hosted systems)?",
            [ip], any_=['网段', '段', 'segment', '硬件', 'host', '端口', 'system'],
            qzh=f"{ip} 的分配情况：网段、硬件、承载系统？")
    # ---- O (24) ----
    for dep in random.sample(ent['departments'], 12):
        kw = dep[:4]
        add('O', 'query_departments', {'search': kw},
            f"Resolve the organization unit whose name contains “{kw}” to its canonical full name.",
            [dep if len(dep) <= 12 else dep[:8]], qzh=f"把含“{kw}”的单位解析成规范全称。")
    for dep in random.sample(ent['departments'], 12):
        add('O', 'get_department_overview', {'department': dep},
            f"Give the security overview of {dep}: responsible officers, contacts and asset counts.",
            [dep if len(dep) <= 12 else dep[:8]], any_=['负责人', '联络', '官员', 'officer', '资产', '管理员'],
            qzh=f"{dep} 的安全概况：责任人、联系人、资产数量。")
    # ---- L (72) ----
    notices = [x for x in ent['notices'] if x['department']]
    for yr in ('2024', '2025', '2026'):
        add('L', 'query_event_notices', {'year': yr},
            f"How many superior-authority security bulletins were recorded in {yr}? Name a couple and the units they concern.",
            [yr], any_=['total', '总数', '通报', '共', 'bulletin'],
            qzh=f"{yr} 年登记了哪些上级通报？数量、点名单位。")
    for x in random.sample(notices, min(8, len(notices))):
        add('L', 'query_event_notices', {'department': x['department']},
            f"List the security bulletins recorded against {x['department']} and their remediation states.",
            [x['department'] if len(x['department']) <= 12 else x['department'][:8]],
            any_=['整改', 'rectification', 'total', '共', '通报'],
            qzh=f"{x['department']} 被哪些通报点过名？整改状态如何。")
    for st in ('未整改', '按时整改', '超时整改'):
        add('L', 'query_event_notices', {'rectification_status': st, 'page_size': '20'},
            f"Which bulletin items are currently “{st}”? Summarize with counts.",
            [st], any_=['total', '总数', '共', '单位', '整改'],
            qzh=f"当前“{st}”的通报项有哪些？给数量。")
    for x in random.sample([y for y in notices if y['title']], min(6, len(notices))):
        kw = x['title'][:6]
        add('L', 'query_event_notices', {'search': kw},
            f"Search bulletins mentioning “{kw}”: which ones and are they closed?",
            any_=[kw, '整改', '通报'], req=[kw] if False else ['通报'],
            qzh=f"搜索涉及“{kw}”的通报：有哪几条、闭环没有。")
    # check_ip_internal (24)
    for ip in ent['internal_ips'][:12]:
        add('L', 'check_ip_internal', {'ip': ip},
            f"Is {ip} a campus IP according to the registered prefix ledger?",
            [ip.split('.')[0] + '.' + ip.split('.')[1]], any_=['是', '校内', 'true', 'campus', '前缀', 'prefix'],
            forb=['不是校内', '未命中'], qzh=f"{ip} 是不是校园 IP？")
    for ip in ent['external_ips'][:12]:
        add('L', 'check_ip_internal', {'ip': ip},
            f"Check whether {ip} belongs to the campus prefix ledger.",
            any_=['不属于', '不是', 'false', 'not', '校外', '未命中'], req=[],
            forb=['是校内', '属于校园'], qzh=f"核验 {ip} 是否属于校园前缀台账。")
    # web logs (10) and DNS logs (5), domains probed to have traffic in the window
    wdoms = ent.get('web_domains') or ['***.edu.cn']
    for i in range(10):
        dm = wdoms[i % len(wdoms)]
        add('L', 'query_web_access_logs', {'domain': dm, 'begin_time': '2026-10-04 00:00:00', 'end_time': '2026-10-10 23:59:59', 'page_size': '10'},
            f"Show web-proxy access hits for {dm} during 2026-10-04..10 (client IPs, URLs, statuses).",
            [dm], any_=['total', '共', '访问', 'hit', '记录', '条'],
            qzh=f"2026-10-04 至 10 期间 {dm} 的代理访问命中情况。")
    # drop bare campus parent domain: 7-day DNS aggregation times out on the ES side
    ddoms = [d for d in (ent.get('dns_domains') or []) if d != '***.edu.cn'] or ent.get('web_domains') or ['***.edu.cn']
    for i in range(5):
        dm = ddoms[i % len(ddoms)]
        add('L', 'query_dns_query_logs', {'domain': dm, 'begin_time': '2026-10-04', 'end_time': '2026-10-10'},
            f"Summarize recursive-DNS lookups of {dm} during 2026-10-04..10: who queried it and what records came back.",
            [dm], any_=['total', '共', '查询', 'record', '记录', '解析', '条'],
            qzh=f"2026-10-04 至 10 对 {dm} 的 DNS 查询汇总。")
    acct = ent['real_accounts'][0]
    for i in range(4):
        add('L', 'query_wireless_auth_logs', {'account': acct,
                                              'begin_time': '2026-10-04', 'end_time': '2026-10-10'},
            f"Did account {acct} authenticate to campus Wi-Fi during 2026-10-04..10? What were the results?",
            any_=['成功', 'success', '失败', 'fail', '认证', 'auth', '结果'], req=[acct],
            qzh=f"账号 {acct} 在 10-04 至 10-10 的 Wi-Fi 认证记录和结果。")
    for st in ('成功', '失败'):
        add('L', 'query_wireless_auth_logs', {'result': st, 'begin_time': '2026-10-08', 'end_time': '2026-10-10', 'page_size': '5'},
            f"How many campus Wi-Fi authentications with result “{st}” were logged on 2026-10-08..10?",
            any_=['失败', 'failed', 'fail', '成功', 'success', 'SUCCESS', '共', '无', '没有'], req=[],
            qzh=f"10-08 至 10-10 结果为{st}的无线认证数量。")
    # ---- T (38) ----
    for ip in ent['black_ip_single'][:3]:
        add('T', 'query_black_ips', {'ip': ip},
            f"Is attacker IP {ip} on the blocklist?",
            [ip], any_=['封锁', '已封', 'blocked', '在册'], qzh=f"{ip} 在黑名单上吗？")
    for cv in ent['covered'][:8]:
        add('T', 'query_black_ips', {'ip': cv['ip']},
            f"Is {cv['ip']} blocked? If the hit comes from a range, state the range explicitly.",
            [cv['cidr']], any_=['封锁', '已封', 'blocked', '网段', '段'],
            qzh=f"{cv['ip']} 被封了吗？若是段覆盖请点明网段。")
    for ip in ent['uncovered_ips'][:10]:
        add('T', 'query_black_ips', {'ip': ip},
            f"Check whether {ip} is currently blocked (per-address or by any covering range).",
            any_=['未找到', '没有', '未封', '无记录', 'not found', '未被', '未命中', '不在'], req=[],
            forb=['已被封锁', '已被封'], qzh=f"查 {ip} 当前是否被封（含段覆盖）。")
    for dm in ent['black_dns'][:6]:
        add('T', 'query_black_dns', {'domain': dm},
            f"Is domain {dm} on the DNS blocklist, and has the block been synchronized?",
            [dm], any_=['已同步', '未同步', '同步', 'synced', '封锁'],
            qzh=f"域名 {dm} 在 DNS 黑名单吗？同步状态？")
    for dm in ('example-blocked-a.test', 'example-blocked-b.test', 'notlisted.example', 'definitely-not-blocked.test'):
        add('T', 'query_black_dns', {'domain': dm},
            f"Is {dm} blocked in the campus DNS sinkhole ledger?",
            any_=['未找到', '没有', '无记录', '未被', 'not found', '未封', '不在'], req=[],
            forb=['已封'], qzh=f"{dm} 被 DNS 黑洞封了吗？")
    for i in range(6):
        ips = [f"192.0.2.{10+i}", f"203.0.113.{20+i}"]
        if i % 2 == 0 and ent['black_ip_single']:
            ips.append(random.choice(ent['black_ip_single']))
        add('T', 'add_black_ip', {'ips': ips, 'reason': 'brute-force attack source'},
            f"Block attacker addresses {', '.join(ips)} for brute-force activity; report per-address outcomes.",
            ips, any_=['确认', '核对', '登记', '模拟', '已存在', '重复', '新增', 'confirm'],
            qzh=f"封禁 {ips}，原因：***；逐条报告结果。")
    for i in range(4):
        doms2 = [f"malware-relay-{i}.test"] + ([random.choice(ent['black_dns'])] if ent['black_dns'] and i % 2 == 0 else [])
        add('T', 'add_black_dns', {'domains': doms2, 'reason': 'C2 domain from bulletin'},
            f"Sinkhole domain(s) {', '.join(doms2)} citing a C2 bulletin; report per-domain outcomes and sync state.",
            doms2, any_=['确认', '核对', '登记', '模拟', '已存在', '重复', '新增', '同步', 'confirm'],
            qzh=f"黑洞域名 {doms2}，原因：通报 C2 域名；逐条报告。")
    # ---- S (23) ----
    for i in range(3):
        add('S', 'get_statistics_report', {},
            "Give the institution-wide security posture summary: units covered, asset scale and bulletin totals.",
            ['82'], any_=['信息系统', '资产', '通报', '硬件', 'system', 'asset'],
            qzh="全校安全治理汇总：单位数、资产规模、通报总量。")
    for dep in random.sample(ent['departments'], 10):
        add('S', 'get_department_statistics_report', {'keyword': dep[:4]},
            f"Pull the per-unit statistics row for “{dep[:4]}…”: asset counts and assessment standing.",
            [dep[:4]], any_=['资产', 'total', '得分', '考核', 'system'],
            qzh=f"拉取含“{dep[:4]}”的单位统计行。")
    for lv in ('二级', '三级', '一级', None):
        args = {'level': lv} if lv else {}
        add('S', 'get_protection_report', args,
            f"Report MLPS (classified-protection) filings and assessment coverage for level “{lv or 'ALL'}”.",
            [lv] if lv else ['备案'], any_=['%', '覆盖率', '备案', '测评', 'coverage', '100'],
            qzh=f"等保{'全部' if not lv else lv}备案与测评覆盖率。")
    for yr in ('2023', '2024', '2025'):
        add('S', 'get_examine_report', {'year': yr},
            f"Which units topped the annual security assessment in {yr} and what were the top scores?",
            [yr], any_=['分', '排名', 'rank', 'score', '考核'],
            qzh=f"{yr} 年度安全考核排名和最高分。")
    exdeps = ent.get('examine_depts') or ent['departments']
    for dep in random.sample(exdeps, min(3, len(exdeps))):
        add('S', 'get_examine_report', {'department': dep},
            f"How did {dep} do in the annual security assessment (score, rank, deductions)?",
            [dep if len(dep) <= 12 else dep[:8]], any_=['分', '扣', '排名', 'score', 'rank'],
            qzh=f"{dep} 的年度安全评分、排名与扣分。")
    # ---- P (20) ----
    projs = [p for p in ent['projects'] if p['id']]
    for p in random.sample(projs, min(6, len(projs))):
        add('P', 'search_projects', {'keyword': (p['name'] or '')[:8]},
            f"Find the maintenance project whose name contains “{(p['name'] or '')[:8]}”: vendor and contract status.",
            [p['id']] if False else [(p['name'] or '')[:6]], any_=['厂商', '供应商', 'vendor', '合同', '维保', p['supplier'] or 'x'],
            qzh=f"检索名称含“{(p['name'] or '')[:6]}”的项目：厂商、合同状态。")
    for st in ('在保', '过保'):
        add('P', 'search_projects', {'warranty_status': st, 'page_size': '20'},
            f"Which projects are currently “{st}” (in warranty / expired)? Summarize vendors.",
            [st], any_=['项目', 'total', '共', '供应商', 'vendor', '无'],
            qzh=f"当前“{st}”的项目有哪些？供应商汇总。")
    for kw in sorted({(p['supplier'] or '')[:4] for p in projs if p['supplier']})[:4]:
        add('P', 'search_projects', {'supplier': kw, 'page_size': '20'},
            f"What has vendor “{kw}…” delivered on campus (projects, warranty, payment)?",
            [kw], any_=['项目', 'total', '共', '维保', '合同'],
            qzh=f"供应商“{kw}”在校内交付了哪些项目？")
    for p in random.sample(projs, min(8, len(projs))):
        add('P', 'get_project_detail', {'project_id': p['id']},
            f"Detail project {p['id']}: funding, installment payments and linked assets.",
            [p['id']], any_=['付', '款', '分期', '合同', 'payment', 'installment'],
            qzh=f"项目 {p['id']} 详情：经费、分期付款、关联资产。")
    # ---- X (15, gold = first hop) ----
    for a in random.sample(ipok, min(5, len(ipok))):
        add('X', 'search_assets', {'keyword': a['ip'], 'field': 'ip'},
            f"For the system at {a['ip']}: what runs there, who administers it, and does it have any unrectified bulletin?",
            [a['id']], any_=[a['admin'] or 'admin', a['department'] or 'dept', '整改', 'remediation', '通报'],
            qzh=f"{a['ip']} 上的系统是什么、谁管、有无未整改通报？")
    for a in random.sample(info, min(5, len(info))):
        add('X', 'get_asset_security', {'asset_id': a['id']},
            f"For asset {a['id']}: check its security profile and tell me whether any bulletin on it remains open, and which unit owns it.",
            [a['id']], any_=['整改', 'remediation', 'open', 'department', '部门'],
            qzh=f"资产 {a['id']}：安全档案有无未闭环通报、归属哪个单位。")
    for dep in random.sample(ent['departments'], 5):
        add('X', 'query_departments', {'search': dep[:4]},
            f"Resolve the unit “{dep[:4]}…”, then summarize its online information systems and any open bulletins against it.",
            [dep[:4]], any_=['信息系统', '通报', 'INFO_', '整改', 'total'],
            qzh=f"解析“{dep[:4]}”单位，汇总其在线系统和未闭环通报。")
    json.dump(tasks, open(T2, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('generated', len(tasks), 'tasks ->', T2)

# ---------------- validate ----------------
def validate():
    tasks = json.load(open(T2, encoding='utf-8'))
    bad = []
    for t in tasks:
        ref = t.get('_ref', '')
        # empty-result payloads legitimately carry no verdict tokens (negative tasks)
        empty = ('"total": 0' in ref) or ('"results": []' in ref) or ('"error"' in ref)
        write = t['gold_tool'] in ('add_black_ip', 'add_black_dns') or ref.startswith('SIMULATED')
        for k in t.get('required_all', []):
            if k not in ref and not write:
                bad.append((t['id'], 'req-missing', k))
        anyt = t.get('required_any', [])
        if anyt and not empty and not write and not any(k in ref for k in anyt):
            bad.append((t['id'], 'any-none-in-ref', None))
    print('validated', len(tasks), 'tasks; issues:', len(bad))
    for b in bad[:40]: print(' ', b)

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'fetch'
    {'fetch': fetch, 'gen': gen, 'validate': validate}[mode]()
