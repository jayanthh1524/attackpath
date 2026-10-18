import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from actions import apply_fix
from analysis import (current_settings, fix_table, open_routes, plan,
                      snapshot)

load_dotenv()
client = OpenAI(base_url="https://integrate.api.nvidia.com/v1",
                api_key=os.environ["NVIDIA_API_KEY"], timeout=120)
MODEL = "nvidia/nemotron-3-super-120b-a12b"


def fmt(routes, limit=20):
    return {'count': len(routes),
            'routes': [' -> '.join(r) for r in routes[:limit]]}


def t_investigate():
    targets, _ = current_settings()
    snap = snapshot(targets)
    routes = open_routes(snap)
    counts = {}
    for r in routes:
        for n in r[1:-1]:
            counts[n] = counts.get(n, 0) + 1
    choke = sorted(counts.items(), key=lambda x: -x[1])[:8]
    return {'protecting': targets, 'open_routes': fmt(routes),
            'chokepoints': [{'computer': n, 'open_routes_through_it': c}
                            for n, c in choke],
            'fix_comparison': [{'fix': f, 'routes_closed': c, 'routes_left': l}
                               for f, c, l in fix_table(snap)[:10]]}


def t_remediate():
    targets, fix_all = current_settings()
    snap = snapshot(targets)
    before = open_routes(snap)
    steps, left, rest = plan(snap, fix_all)
    for s in steps:
        apply_fix(s['fix'], f"Closes {s['closes']} open routes to "
                  f"{', '.join(targets)}; {s['routes_left']} left")
    return {'fixes_applied_in_order': steps, 'routes_before': len(before),
            'routes_after': len(left), 'remaining_routes': fmt(left),
            'weaknesses_still_open': rest[:15]}


TOOL_FUNCS = {'investigate': t_investigate, 'remediate': t_remediate}
TOOLS = [
    {"type": "function", "function": {
        "name": "investigate",
        "description": "Find the open attack routes to the protected systems, "
                       "the chokepoints, and compare every available fix.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "remediate",
        "description": "Apply the best fix plan to the graph, one fix at a time, "
                       "until no attack route is left, and record each decision.",
        "parameters": {"type": "object", "properties": {}}}},
]

SYSTEM = """You are AttackPath, a security triage agent.
1. Call investigate to see the open attack routes, the chokepoints and the fix comparison.
2. Call remediate to apply the best fix plan.
3. Write a short report in plain English: routes before, the fixes applied in order and why (name the routes each closes), routes after, any remaining risk, and one next step.
Use only the names and numbers returned by the tools."""


def run_agent(question, max_steps=6):
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": question}]
    for step in range(max_steps):
        print(f"  [thinking... step {step + 1}]", flush=True)
        resp = client.chat.completions.create(
            model=MODEL, messages=messages, tools=TOOLS,
            tool_choice="auto", max_tokens=1800)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            return msg.content or "(no answer)"
        messages.append({
            "role": "assistant", "content": msg.content or "",
            "tool_calls": [{"id": c.id, "type": "function",
                            "function": {"name": c.function.name,
                                         "arguments": c.function.arguments}}
                           for c in msg.tool_calls]})
        for call in msg.tool_calls:
            name = call.function.name
            try:
                result = TOOL_FUNCS[name]()
            except Exception as e:
                result = {"error": str(e)}
            print(f"  [agent used tool] {name}", flush=True)
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": json.dumps(result)})
    return "Stopped: too many steps."
