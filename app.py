import contextlib
import hashlib
import uuid
from datetime import datetime

import streamlit as st

from actions import reset_demo
from agent import run_agent
from analysis import fix_table, open_routes, snapshot, use_settings
from loader import DEMO, allow_run, load_network, parse_csv, to_csv
from tools import get_graph, use_graph

st.set_page_config(page_title="AttackPath", layout="wide")
ss = st.session_state


def graph_dot(net, routes, targets, weak):
    # drawn from the network data itself, so it needs no database queries
    hot = {(a, b) for r in routes for a, b in zip(r, r[1:])}
    lines = ['digraph G {', 'rankdir=LR;',
             'node [shape=box, style="rounded,filled", '
             'fillcolor="#eeeeee", fontname="Helvetica"];',
             '"Internet" [fillcolor="#ffcdd2"];']
    for name in net["assets"]:
        color = ("#c8e6c9" if name in targets
                 else "#ffe0b2" if name in weak else "#eeeeee")
        lines.append(f'"{name}" [fillcolor="{color}"];')
    for a, b in [("Internet", x) for x in net["exposed"]] + list(net["links"]):
        style = ('color="red", penwidth=2.5' if (a, b) in hot
                 else 'color="#999999"')
        lines.append(f'"{a}" -> "{b}" [{style}];')
    lines.append("}")
    return "\n".join(lines)


def view(net, targets):
    ck = (ss["loaded"], tuple(targets))
    cache = ss.get("rroutes") if ss.get("rck") == ck else None
    snap = snapshot(targets, cache)
    ss["rroutes"], ss["rck"] = snap["routes"], ck
    routes = open_routes(snap)
    weak = set(snap["vulns"].values())
    return snap, routes, graph_dot(net, routes, targets, weak)


def decisions():
    res = get_graph().query(
        "MATCH (d:Decision)-[:APPLIED]->(f:Fix) "
        "RETURN f.action, d.reason ORDER BY d.time").result_set
    seen, out = set(), []
    for a, r in res:
        if (a, r) not in seen:
            seen.add((a, r))
            out.append((a, r))
    return out


def build_report(label, targets, before, after, table, applied, text):
    L = ["# AttackPath security triage report", "",
         f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
         f"Network: {label}", f"Systems protected: {', '.join(targets)}", "",
         f"## Open attack routes before ({len(before)})"]
    L += [f"- {' -> '.join(r)}" for r in before] or ["- none"]
    L += ["", "## Fix comparison at the start (simulated on the graph)", "",
          "| Fix | Routes closed | Routes left |", "|---|---|---|"]
    L += [f"| {f} | {c} | {left} |" for f, c, left in table]
    L += ["", "## Fixes applied, in order"]
    L += [f"{i}. {a}: {r}" for i, (a, r) in enumerate(applied, 1)] or ["- none"]
    L += ["", f"## Open attack routes after ({len(after)})"]
    L += [f"- {' -> '.join(r)}" for r in after] or ["- none"]
    L += ["", "## Agent report", "", text, "", "---",
          "Routes and fix results come from graph queries on the data "
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


if "gid" not in ss:
    ss["gid"] = "s_" + uuid.uuid4().hex[:8]  # a private graph per visitor
    ss["loaded"], ss["runs"] = None, 0
use_graph(ss["gid"])

st.title("AttackPath: a graph-powered security triage agent")
st.caption("FalkorDB finds the attack routes. NVIDIA Nemotron chooses the "
           "tools, applies the fix plan and explains it.")

with st.expander("Judge quick start (2 minutes)", expanded=True):
    st.markdown(
        "1. Use the **built-in demo** (simulated), or **upload your own "
        "network** (download the CSV template to see the format).\n"
        "2. Pick the **systems to protect**. **Red lines** are routes an "
        "attacker can use to reach them.\n"
        "3. Click **Run the agent**. It investigates, then applies a full fix "
        "plan until no route is left.\n"
        "4. Read the before/after graphs and **download the report**.")

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

assets = list(net["assets"])
if key == "demo":
    default = ["Database"]
else:
    has_out = {a for a, _ in net["links"]}
    default = ([a for a in assets if a not in has_out
                and a not in net["exposed"]] or assets[:1])
targets = st.multiselect("Systems to protect", assets, default=default,
                         key=f"tg_{key}")
if not targets:
    st.warning("Pick at least one system to protect.")
    st.stop()
fix_all = st.checkbox("Also fix every weakness, not only those on attack routes")
reset_first = st.checkbox("Reset to the starting state before running",
                          value=True)
use_settings(targets, fix_all)
if st.button("Reset now"):
    reset_demo()
    ss.pop("result", None)

snap, routes, dot = view(net, targets)
st.subheader("Network now")
st.metric("Open attack routes to the protected systems", len(routes))
st.graphviz_chart(dot)

st.divider()
names = ", ".join(targets)
incident = st.text_area(
    "Incident",
    f"A critical vulnerability was just reported. Investigate the risk to "
    f"{names} and fix what you can.", key=f"inc_{key}_{names}")

if st.button("Run the agent", type="primary"):
    if ss["runs"] >= 6:
        st.warning("Run limit reached for this session.")
    elif not allow_run():
        st.warning("The demo is busy (hourly AI limit). Try again later.")
    else:
        ss["runs"] += 1
        if reset_first:
            reset_demo()
        snap0, before, _ = view(net, targets)
        table = fix_table(snap0)
        st.write("Agent working...")
        log = LiveLog(st.empty())
        with contextlib.redirect_stdout(log):
            try:
                report = run_agent(f"{incident} Systems to protect: {names}.")
            except Exception as e:
                report = f"The AI call failed: {e}"
        _, after, after_dot = view(net, targets)
        _, _, before_dot = view(net, targets) if False else (None, None, None)
        ss["result"] = {
            "before_n": len(before), "after_n": len(after),
            "before_dot": graph_dot(net, before, targets,
                                    set(snap0["vulns"].values())),
            "after_dot": after_dot, "report": report, "steps": log.text,
            "md": build_report(label, targets, before, after, table,
                               decisions(), report)}

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
