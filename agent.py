import os
import json
from dotenv import load_dotenv
from openai import OpenAI

from tools import find_attack_paths, simulate_fix, list_fixes
from actions import apply_fix, reset_demo
from algorithms import route_chokepoints

load_dotenv()
client = OpenAI(base_url="https://integrate.api.nvidia.com/v1",
                api_key=os.environ["NVIDIA_API_KEY"], timeout=120)
MODEL = "nvidia/nemotron-3-super-120b-a12b"


# ---- the tools the AI can use (wrappers around our own functions) ----
def t_find_routes(target='Database'):
    routes = find_attack_paths(target)
    return {'count': len(routes), 'routes': [' -> '.join(r) for r in routes]}


def t_find_chokepoints(target='Database'):
    return [{'computer': n, 'open_routes_through_it': c}
            for n, c in route_chokepoints(target)]


def t_compare_fixes(target='Database'):
    out = []
    for fix in list_fixes():
        before, after = simulate_fix(fix, target)
        out.append({'fix': fix, 'routes_closed': len(before) - len(after),
                    'routes_left': len(after)})
    return sorted(out, key=lambda x: x['routes_closed'], reverse=True)


def t_apply_fix(fix, reason, target='Database'):
    apply_fix(fix, reason)
    return {'applied': fix, 'routes_left': len(find_attack_paths(target))}


TOOL_FUNCS = {'find_routes': t_find_routes,
              'find_chokepoints': t_find_chokepoints,
              'compare_fixes': t_compare_fixes,
              'apply_fix': t_apply_fix}


# ---- the menu we show the AI: each tool's name and what it does ----
def schema(name, desc, props, required):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props,
                       "required": required}}}


TARGET = {"target": {"type": "string",
                     "description": "Computer to protect. Default is Database."}}
TOOLS = [
    schema("find_routes",
           "List every open attack route from the Internet to the target.",
           TARGET, []),
    schema("find_chokepoints",
           "Count how many open attack routes pass through each computer.",
           TARGET, []),
    schema("compare_fixes",
           "Test every fix and report how many routes each one closes.",
           TARGET, []),
    schema("apply_fix",
           "Apply one fix and record the reason in the graph.",
           {"fix": {"type": "string",
                    "description": "Exact fix name from compare_fixes"},
            "reason": {"type": "string",
                       "description": "Why this fix was chosen"}},
           ["fix", "reason"]),
]

SYSTEM = """You are AttackPath, a security triage agent for a company network.
Work step by step with your tools:
1. find_routes to see the open attack routes,
2. find_chokepoints to see which computers sit on the most routes,
3. compare_fixes to test every fix,
4. apply_fix with the fix that closes the most routes,
5. find_routes again to verify the result.
Then write a short report in plain English: routes before, the fix you chose
and why (name the routes it closes), routes after, and a suggested next step.
Only use fix names returned by compare_fixes."""


def run_agent(question, max_steps=8):
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": question}]
    for step in range(max_steps):
        print(f"  [thinking... step {step + 1}]", flush=True)
        resp = client.chat.completions.create(
            model=MODEL, messages=messages, tools=TOOLS,
            tool_choice="auto", max_tokens=2000)
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
                args = json.loads(call.function.arguments or "{}")
            except Exception:
                args = {}
            try:
                result = TOOL_FUNCS[name](**args)
            except Exception as e:
                result = {"error": str(e)}
            print(f"  [agent used tool] {name} {args}", flush=True)
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": json.dumps(result)})
    return "Stopped: too many steps."


if __name__ == "__main__":
    reset_demo()
    question = ("A critical vulnerability was just reported on our Web Server. "
                "Investigate the risk to the Database and fix what you can.")
    print("QUESTION:", question, "\n", flush=True)
    try:
        print("\nREPORT:\n" + run_agent(question))
    except Exception as e:
        print("The AI call failed:", str(e)[:300])
