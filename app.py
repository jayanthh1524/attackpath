import contextlib

import streamlit as st

from actions import reset_demo
from agent import run_agent
from tools import find_attack_paths, get_graph, open_vulns

st.set_page_config(page_title="AttackPath", layout="wide")


def graph_dot(routes):
    # draws the network; routes an attacker can use are drawn in red
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
        if name == "Database":
            color = "#c8e6c9"
        elif name in weak:
            color = "#ffe0b2"
        else:
            color = "#eeeeee"
        lines.append(f'"{name}" [fillcolor="{color}"];')
    edges = g.query("MATCH (a)-[:EXPOSES|CONNECTS_TO]->(b) "
                    "RETURN a.name, b.name").result_set
    for a, b in edges:
        style = ('color="red", penwidth=2.5' if (a, b) in hot
                 else 'color="#999999"')
        lines.append(f'"{a}" -> "{b}" [{style}];')
    lines.append("}")
    return "\n".join(lines)


def current_view():
    routes = find_attack_paths("Database")
    return routes, graph_dot(routes)


class LiveLog:
    # catches the agent's printed steps and shows them on the page live
    def __init__(self, box):
        self.box = box
        self.text = ""
        self.busy = False

    def write(self, s):
        self.text += s
        if not self.busy:
            self.busy = True
            self.box.code(self.text)
            self.busy = False
        return len(s)

    def flush(self):
        pass


st.title("AttackPath: a graph-powered security triage agent")
st.caption("FalkorDB finds the attack routes. NVIDIA Nemotron chooses the "
           "tools, picks the fix and explains it. Demo data is simulated.")

with st.expander("Judge quick start (2 minutes)", expanded=True):
    st.markdown(
        "1. Look at the network below. **Red lines** are routes an attacker "
        "can use to reach the Database.\n"
        "2. Click **Run the agent**. It investigates, compares every fix, "
        "applies the best one and re-checks.\n"
        "3. Read the before/after graphs and the report. Every number comes "
        "from graph queries.")

reset_first = st.checkbox("Reset to the starting state before running",
                          value=True)
if st.button("Reset demo now"):
    reset_demo()
    st.session_state.pop("result", None)

routes, dot = current_view()
st.subheader("Network now")
st.metric("Open attack routes to the Database", len(routes))
st.graphviz_chart(dot)

st.divider()
question = st.text_area(
    "Incident",
    "A critical vulnerability was just reported on our Web Server. "
    "Investigate the risk to the Database and fix what you can.")

if st.button("Run the agent", type="primary"):
    if reset_first:
        reset_demo()
    before_routes, before_dot = current_view()
    st.write("Agent working... this can take 1-3 minutes.")
    log = LiveLog(st.empty())
    with contextlib.redirect_stdout(log):
        try:
            report = run_agent(question)
        except Exception as e:
            report = f"The AI call failed: {e}"
    after_routes, after_dot = current_view()
    st.session_state["result"] = {
        "before_n": len(before_routes), "before_dot": before_dot,
        "after_n": len(after_routes), "after_dot": after_dot,
        "report": report, "steps": log.text}

res = st.session_state.get("result")
if res:
    st.subheader("Result")
    c1, c2 = st.columns(2)
    c1.metric("Open routes before", res["before_n"])
    c1.graphviz_chart(res["before_dot"])
    c2.metric("Open routes after", res["after_n"])
    c2.graphviz_chart(res["after_dot"])
    st.subheader("Agent report")
    st.write(res["report"])
    with st.expander("Agent steps (tool calls)"):
        st.code(res["steps"])
