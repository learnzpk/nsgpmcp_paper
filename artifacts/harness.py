#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N1 evaluation harness (stdlib-only).

Modes:
  --freeze   call each task's gold tool+args on the production MCP server,
             store the reference payload into tasks file (_ref field).
  --run      run agent arms against an OpenAI-compatible chat endpoint:
               --arm full | ablated | bare
             scores TS / TSA / AF1, writes JSONL results.

Safety:
  - write-capable tools (add_black_ip, add_black_dns) are NEVER executed;
    the harness intercepts and returns a simulated registration response.
  - query_problem_mails is excluded from the suite (its search registers
    ledger rows; kept out of automated evaluation by design).
  - credentials only via environment: MCP_TOKEN, MCP_URL, LLM_BASE, LLM_KEY, LLM_MODEL.

Ablation: guardrail sentences (R1-R4) are stripped from tool descriptions
by regex before handing definitions to the model.
"""
import argparse, json, os, re, ssl, sys, time, urllib.request, urllib.error

WRITE_TOOLS = {"add_black_ip", "add_black_dns"}
GUARD_PATTERNS = [
    r"查不到[^。\n]*[。]?", r"不代表[^。\n]*[。]?", r"不等于[^。\n]*[。]?",
    r"如实[^。\n]*[。]?", r"不要[^。\n]*[。]?", r"须[^。\n]*[。]?",
    r"务必[^。\n]*[。]?", r"不得[^。\n]*[。]?",
    r"只有[^。\n]*才[^。\n]*[。]?", r"须说明[^。\n]*[。]?",
]

# ---------- MCP client (streamable-http) ----------
class Mcp:
    def __init__(self, url, token):
        self.url, self.token, self.sid, self.rid = url, token, None, 0

    def _post(self, payload):
        self.rid += 1
        body = json.dumps({**payload, "id": self.rid,
                           "jsonrpc": "2.0"} if "method" in payload else payload).encode()
        for attempt in range(6):
            req = urllib.request.Request(self.url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Accept": "application/json, text/event-stream",
                         "Authorization": "Token " + self.token,
                         **({"Mcp-Session-Id": self.sid} if self.sid else {})})
            try:
                resp = urllib.request.urlopen(req, timeout=120)
                break
            except urllib.error.HTTPError as e:
                if e.code == 404 and self.sid and not payload.get("method", "").startswith("initialize"):
                    self.sid = None
                    self.init()          # session lost -> re-init once
                    continue
                transient = e.code in (429, 500, 502, 503, 504)
                if not transient or attempt == 5:
                    raise
                time.sleep(3 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 5:
                    raise
                time.sleep(3 * (attempt + 1))
        raw = resp.read().decode("utf-8", "ignore")
        if not self.sid:
            self.sid = resp.headers.get("mcp-session-id")
        m = re.search(r"data: (\{.*\})", raw)
        return json.loads(m.group(1)) if m else json.loads(raw) if raw.strip() else {}

    def init(self):
        d = self._post({"method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "n1-eval-harness", "version": "1.0"}}})
        self._post({"method": "notifications/initialized"})
        return d

    def tools_list(self):
        return self._post({"method": "tools/list", "params": {}})["result"]["tools"]

    def call(self, name, args):
        d = self._post({"method": "tools/call",
                        "params": {"name": name, "arguments": args}})
        if "error" in d:
            return "ERROR: " + json.dumps(d["error"], ensure_ascii=False)
        return "".join(c.get("text", "") for c in d["result"]["content"])

# ---------- LLM client (OpenAI-compatible, function calling) ----------
def chat(base, key, model, messages, tools=None, temperature=0.1):
    payload = {"model": model, "messages": messages, "temperature": temperature}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    for attempt in range(6):
        req = urllib.request.Request(base.rstrip("/") + "/v1/chat/completions",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 5:
                raise
            time.sleep(4 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 5:
                raise
            time.sleep(4 * (attempt + 1))

def strip_guardrails(desc):
    out = desc
    for pat in GUARD_PATTERNS:
        out = re.sub(pat, "", out)
    return re.sub(r"\s{2,}", " ", out).strip()

def to_openai_tools(mcp_tools, ablate):
    out = []
    for t in mcp_tools:
        d = t.get("description", "")
        out.append({"type": "function", "function": {
            "name": t["name"],
            "description": strip_guardrails(d) if ablate else d,
            "parameters": t.get("inputSchema", {"type": "object", "properties": {}})}})
    return out

SYS_PROMPT = ("You are a campus security operations assistant. Answer ONLY from tool "
              "observations; never invent records. Use tools when needed, then answer "
              "concisely in the user's language.")
SIMULATED_WRITE = {"simulated": True,
                   "note": "evaluation harness: registration simulated, not executed"}

# ---------- agent loop ----------
def run_agent(task, mcp, tools, cfg, max_steps=6):
    msgs = [{"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": task["query"]}]
    trace, t_start, used = [], time.perf_counter(), 0
    first_tool, arg_slots = None, {}
    for _ in range(max_steps):
        resp = chat(cfg["base"], cfg["key"], cfg["model"], msgs, tools or None)
        msg = resp["choices"][0]["message"]
        msgs.append(msg)
        if not msg.get("tool_calls"):
            break
        for tc in msg["tool_calls"]:
            raw_args = tc["function"].get("arguments")
            if isinstance(raw_args, str):
                raw_args = json.loads(raw_args or "{}")
            fn, args = tc["function"]["name"], (raw_args or {})
            used += 1
            t0 = time.perf_counter()
            if fn in WRITE_TOOLS:
                obs, ms = json.dumps(SIMULATED_WRITE), 0
            else:
                obs = mcp.call(fn, args)
                ms = int((time.perf_counter() - t0) * 1000)
            if first_tool is None:
                first_tool, arg_slots = fn, args
            trace.append({"tool": fn, "args": args, "ms": ms, "obs_len": len(obs),
                          "obs": obs[:8000]})
            msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": obs[:8000]})
    final = msgs[-1].get("content", "") or ""
    return {"query": task["id"], "final": final, "trace": trace,
            "first_tool": first_tool, "first_args": arg_slots,
            "calls": used, "e2e_ms": int((time.perf_counter() - t_start) * 1000)}

# ---------- scoring ----------
def score(task, run):
    ans = run["final"] or ""
    req = task.get("required_all", [])
    any_ = task.get("required_any", [])
    forb = task.get("forbidden", [])
    ts = (all(k.lower() in ans.lower() for k in req)
          and (not any_ or any(k.lower() in ans.lower() for k in any_))
          and not any(k.lower() in ans.lower() for k in forb))
    tsa = run["first_tool"] == task.get("gold_tool")
    gold = task.get("gold_args", {})
    hit = sum(1 for k, v in gold.items()
              if str(run["first_args"].get(k, "")).strip().lower()
              == str(v).strip().lower())
    af1 = (hit / len(gold)) if gold else (1.0 if tsa else 0.0)
    return {"ts": ts, "tsa": tsa, "af1": round(af1, 3)}

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", required=True)
    ap.add_argument("--mode", choices=["freeze", "run"], required=True)
    ap.add_argument("--arm", choices=["full", "ablated", "bare"], default="full")
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    tasks = json.load(open(a.tasks, encoding="utf-8"))
    if a.limit:
        tasks = tasks[:a.limit]
    if a.mode == "run" and os.path.exists(a.out):
        done = set()
        for ln in open(a.out, encoding="utf-8"):
            try:
                done.add(json.loads(ln)["task"])
            except Exception:
                pass
        if done:
            tasks = [t for t in tasks if t["id"] not in done]
            print("resume:", len(done), "done,", len(tasks), "remaining")
    mcp = Mcp(os.environ["MCP_URL"], os.environ["MCP_TOKEN"])
    mcp.init()
    all_tools = mcp.tools_list()

    if a.mode == "freeze":
        for t in tasks:
            obs = ("SIMULATED (write tool, not executed)"
                   if t["gold_tool"] in WRITE_TOOLS else mcp.call(t["gold_tool"], t["gold_args"]))
            t["_ref"] = obs[:8000]
            print("frozen", t["id"], len(obs), "chars")
        json.dump(tasks, open(a.tasks, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("references frozen ->", a.tasks)
        return

    cfg = {"base": os.environ["LLM_BASE"], "key": os.environ["LLM_KEY"],
           "model": os.environ["LLM_MODEL"]}
    tools = ([] if a.arm == "bare"
             else to_openai_tools(all_tools, ablate=(a.arm == "ablated")))
    stats = {"n": 0, "ts": 0, "tsa": 0, "af1": 0.0}
    with open(a.out, "a", encoding="utf-8") as fh:
        for t in tasks:
            run = run_agent(t, mcp, tools, cfg)
            s = score(t, run)
            stats["n"] += 1
            stats["ts"] += int(s["ts"]); stats["tsa"] += int(s["tsa"])
            stats["af1"] += s["af1"]
            fh.write(json.dumps({"arm": a.arm, "task": t["id"], **s,
                                 **run}, ensure_ascii=False) + "\n")
            print(t["id"], s, "calls=%d" % run["calls"], "e2e=%dms" % run["e2e_ms"])
    n = max(stats["n"], 1)
    print("SUMMARY arm=%s n=%d TS=%.1f%% TSA=%.1f%% AF1=%.3f" %
          (a.arm, stats["n"], 100 * stats["ts"] / n, 100 * stats["tsa"] / n, stats["af1"] / n))

if __name__ == "__main__":
    main()
