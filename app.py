import contextlib
import hashlib
import uuid
from datetime import datetime

import streamlit as st

from actions import reset_demo
from agent import run_agent
from loader import DEMO, allow_run, load_network, parse_csv, to_csv
from tools import (find_attack_paths, get_graph, list_fixes, open_vulns,
                   simulate_fix, use_graph, use_target)

st.set_page_config(page_title="AttackPath", layout="wide")


def graph_dot(routes, target):
    g = get_graph()
    hot = set()
    for r in routes:
        for a, b in zip(r, r[1:]):
            hot.add((a, b))
    weak = {a for a, _ in open_vulns(g)}
    lines = ['digraph G {', 'rankdir=LR;',
             'node [shape=box, style="rounded,filled", '
             'fillcolor="#eeeeee", fontname="Helvetica"];',
             '"Internet" [fillcolor="#ffcdd2"];']
    for (name,) in g.query("MATCH (a:Asset) RETURN a.name").result_set:
        color = ("#c8e6c9" if name == target
                 else "#ffe0b2" if name in weak else "#eeeeee")
        lines.append(f'"{name}" [fillcolor="{color}"];')
    edges = g.query("MATCH (a)-[:EXPOSES|CONNECTS_TO]->(b) "
                    "RETURN a.name, b.name").result_set
    for a, b in edges:
        style = ('color="red", penwidth=2.5' if (a, b) in hot
                 else 'color="#999999"')
        lines.append(f'"{a}" -> "{b}" [{style}];')
    lines.append("}")
    return "\n".join(lines)


def current_view(target):
    routes = find_attack_paths(target)
    return routes, graph_dot(routes, target)


def fix_table(target):
    rows = []
    for fix in list_fixes():
        before, after = simulate_fix(fix, target)
        rows.append((fix, len(before) - len(after), len(after)))
    return sorted(rows, key=lambda r: -r[1])


def latest_decision():
    res = get_graph().query(
        "MATCH (d:Decision)-[:APPLIED]->(f:Fix) "
        "RETURN f.action, d.reason ORDER BY d.time DESC LIMIT 1").result_set
    return res[0] if res else None


def build_report(label, target, before, after, table, decision, agent_text):
    L = ["# AttackPath security triage report", "",
         f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
         f"Network: {label}", f"System protected: {target}", "",
         f"## Open attack routes before ({len(before)})"]
    L += [f"- {' -> '.join(r)}" for r in before] or ["- none"]
    L += ["", "## Fix comparison (simulated on the graph)", "",
          "| Fix | Routes closed | Routes left |", "|---|---|---|"]
    L += [f"| {f} | {c} | {left} |" for f, c, left in table]
    L += ["", "## Fix applied"]
    if decision:
        L += [f"- Fix: {decision[0]}", f"- Reason recorded in the graph: {decision[1]}"]
    else:
        L += ["- No fix was applied."]
    L += ["", f"## Open attack routes after ({len(after)})"]
    L += [f"- {' -> '.join(r)}" for r in after] or ["- none"]
    L += ["", "## Agent report", "", agent_text, "",
          "---", "Routes and fix results come from graph queries on the data "
          "provided. Fixes are simulated recommendations; no real system was "
          "changed."]
    return "\n".join(L)


class LiveLog:
    def __init__(self, box):
        self.box, self.text = box, ""

    def write(self, s):
        self.text += s
        self.box.code(self.text)
        return len(s)

    def flush(self):
        pass


ss = st.session_state
if "gid" not in ss:
    ss["gid"] = "s_" + uuid.uuid4().hex[:8]  # a private graph per visitor
    ss["loaded"], ss["runs"] = None, 0
use_graph(ss["gid"])

st.title("AttackPath: a graph-powered security triage agent")
st.caption("FalkorDB finds the attack routes. NVIDIA Nemotron chooses the "
           "tools, picks the fix and explains it.")

with st.expander("Judge quick start (2 minutes)", expanded=True):
    st.markdown(
        "1. Use the **built-in demo** (simulated), or choose **Upload your own "
        "network** and download the CSV template to see the format.\n"
        "2. **Red lines** are routes an attacker can use to reach the system "
        "you protect.\n"
        "3. Click **Run the agent**. It investigates, compares every fix, "
        "applies the best one and re-checks.\n"
        "4. Read the before/after graphs, then **download the report**.")

mode = st.radio("Network to analyze",
                ["Built-in demo (simulated)", "Upload your own network (CSV)"],
                horizontal=True)
if mode.startswith("Built-in"):
    net, label, key = DEMO, "Built-in demo network (simulated)", "demo"
else:
    st.warning("Do not upload sensitive or confidential data to this public "
               "demo. Your network is analyzed in a private temporary graph.")
    st.download_button("Download CSV template (the demo network)",
                       to_csv(DEMO), "attackpath_template.csv", "text/csv")
    st.caption("kind = exposed (reachable from the Internet), connection "
               "(name -> target) or weakness (name, id, severity, fix). "
               "Max 25 computers, 60 connections.")
    up = st.file_uploader("Your network CSV", type=["csv"])
    if up is None:
        st.stop()
    text = up.getvalue().decode("utf-8-sig", errors="replace")
    net, errors = parse_csv(text)
    if errors:
        for e in errors:
            st.error(e)
        st.stop()
    label = f"Uploaded network: {up.name}"
    key = hashlib.md5(text.encode()).hexdigest()

if ss["loaded"] != key:
    with st.spinner("Loading the network into the graph..."):
        load_network(ss["gid"], net)
    ss["loaded"] = key
    ss.pop("result", None)

assets = sorted(net["assets"])
default = assets.index("Database") if "Database" in assets else 0
target = st.selectbox("System to protect", assets, index=default)
use_target(target)

reset_first = st.checkbox("Reset to the starting state before running",
                          value=True)
if st.button("Reset now"):
    reset_demo()
    ss.pop("result", None)

routes, dot = current_view(target)
st.subheader("Network now")
st.metric(f"Open attack routes to {target}", len(routes))
st.graphviz_chart(dot)

st.divider()
incident = st.text_area(
    "Incident",
    f"A critical vulnerability was just reported. Investigate the risk to "
    f"{target} and fix what you can.", key=f"inc_{target}")

if st.button("Run the agent", type="primary"):
    if ss["runs"] >= 6:
        st.warning("Run limit reached for this session.")
    elif not allow_run():
        st.warning("The demo is busy (hourly AI limit). Try again later.")
    else:
        ss["runs"] += 1
        if reset_first:
            reset_demo()
        before, before_dot = current_view(target)
        table = fix_table(target)
        st.write("Agent working... this can take 1-3 minutes.")
        log = LiveLog(st.empty())
        with contextlib.redirect_stdout(log):
            try:
                report = run_agent(f"{incident} The system to protect is "
                                   f"'{target}'.")
            except Exception as e:
                report = f"The AI call failed: {e}"
        after, after_dot = current_view(target)
        ss["result"] = {
            "before_n": len(before), "before_dot": before_dot,
            "after_n": len(after), "after_dot": after_dot, "report": report,
            "steps": log.text,
            "md": build_report(label, target, before, after, table,
                               latest_decision(), report)}

res = ss.get("result")
if res:
    st.subheader("Result")
    c1, c2 = st.columns(2)
    c1.metric("Open routes before", res["before_n"])
    c1.graphviz_chart(res["before_dot"])
    c2.metric("Open routes after", res["after_n"])
    c2.graphviz_chart(res["after_dot"])
    st.subheader("Agent report")
    st.write(res["report"])
    st.download_button("Download the full report (Markdown)", res["md"],
                       "attackpath_report.md", "text/markdown")
    with st.expander("Agent steps (tool calls)"):
        st.code(res["steps"])
