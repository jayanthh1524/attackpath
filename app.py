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


def view(net, targets, kind):
    ck = (ss[f"{kind}_loaded"], tuple(targets))
    cache = ss.get(f"{kind}_rroutes") if ss.get(f"{kind}_rck") == ck else None
    snap = snapshot(targets, cache)
    ss[f"{kind}_rroutes"], ss[f"{kind}_rck"] = snap["routes"], ck
    routes = open_routes(snap)
    weak = set(snap["vulns"].values())
    return snap, routes, graph_dot(net, routes, targets, weak)


def read_sample(name):
    try:
        return open(f"samples/{name}.csv").read()
    except OSError:
        return None


def get_network(kind):
    # returns (network, label, key), or None when nothing is ready yet
    if kind == "demo":
        st.info("The story: a small company's network (simulated). Orange = a "
                "computer with an open weakness, green = the system we "
                "protect, red lines = routes an attacker can use. Click "
                "**Run the agent** and watch it investigate, apply fixes "
                "and prove the result.")
        return DEMO, "Built-in demo network (simulated)", "demo"
    st.warning("Do not upload sensitive or confidential data to this public "
               "demo. Your network is analyzed in a private temporary graph.")
    c1, c2, c3 = st.columns(3)
    c1.download_button("CSV template", to_csv(DEMO),
                       "attackpath_template.csv", "text/csv", key="dl_t")
    for col, name, nice in ((c2, "startup", "Sample: solo founder"),
                            (c3, "office", "Sample: small office")):
        data = read_sample(name)
        if data:
            col.download_button(nice, data, f"{name}.csv", "text/csv",
                                key=f"dl_{name}")
    st.caption("kind = exposed (reachable from the Internet), connection "
               "(name -> target) or weakness (name, id, severity, fix). "
               "Max 25 computers, 60 connections. Pick the valuable systems "
               "(for example customer data), not the entry points.")
    up = st.file_uploader("Your network CSV", type=["csv"], key="own_up")
    if up is None:
        return None
    text = up.getvalue().decode("utf-8-sig", errors="replace")
    net, errors = parse_csv(text)
    if errors:
        for e in errors:
            st.error(e)
        return None
    return (net, f"Uploaded network: {up.name}",
            hashlib.md5(text.encode()).hexdigest())


def workspace(kind):
    gk, lk, rk = f"{kind}_gid", f"{kind}_loaded", f"{kind}_result"
    if gk not in ss:
        ss[gk] = f"s_{kind[0]}{uuid.uuid4().hex[:8]}"  # private graph
        ss[lk] = None
    use_graph(ss[gk])
    got = get_network(kind)
    if got is None:
        return
    net, label, key = got
    if ss[lk] != key:
        with st.spinner("Loading the network into the graph..."):
            load_network(ss[gk], net)
        ss[lk] = key
        ss.pop(rk, None)

    assets = list(net["assets"])
    if kind == "demo":
        default = ["Database"]
    else:
        has_out = {a for a, _ in net["links"]}
        default = ([a for a in assets if a not in has_out
                    and a not in net["exposed"]] or assets[:1])
    targets = st.multiselect("Systems to protect", assets, default=default,
                             key=f"{kind}_tg_{key}")
    if not targets:
        st.warning("Pick at least one system to protect.")
        return
    fix_all = st.checkbox("Also fix every weakness, not only those on attack "
                          "routes", key=f"{kind}_fa")
    reset_first = st.checkbox("Reset to the starting state before running",
                              value=True, key=f"{kind}_rf")
    use_settings(targets, fix_all)
    if st.button("Reset now", key=f"{kind}_reset"):
        reset_demo()
        ss.pop(rk, None)

    snap, routes, dot = view(net, targets, kind)
    st.subheader("Network now")
    st.metric("Open attack routes to the protected systems", len(routes))
    st.graphviz_chart(dot)

    st.divider()
    names = ", ".join(targets)
    incident = st.text_area(
        "Incident",
        f"A critical vulnerability was just reported. Investigate the risk to "
        f"{names} and fix what you can.", key=f"{kind}_inc_{key}_{names}")

    if st.button("Run the agent", type="primary", key=f"{kind}_run"):
        if ss["runs"] >= 6:
            st.warning("Run limit reached for this session.")
        elif not allow_run():
            st.warning("The demo is busy (hourly AI limit). Try again later.")
        else:
            ss["runs"] += 1
            if reset_first:
                reset_demo()
            snap0, before, before_dot = view(net, targets, kind)
            table = fix_table(snap0)
            st.write("Agent working...")
            log = LiveLog(st.empty())
            with contextlib.redirect_stdout(log):
                try:
                    report = run_agent(f"{incident} Systems to protect: "
                                       f"{names}.")
                except Exception as e:
                    report = f"The AI call failed: {e}"
            _, after, after_dot = view(net, targets, kind)
            ss[rk] = {
                "before_n": len(before), "after_n": len(after),
                "before_dot": before_dot, "after_dot": after_dot,
                "report": report, "steps": log.text,
                "md": build_report(label, targets, before, after, table,
                                   decisions(), report)}

    res = ss.get(rk)
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
                           "attackpath_report.md", "text/markdown",
                           key=f"{kind}_dl")
        with st.expander("Agent steps (tool calls)"):
            st.code(res["steps"])


ss.setdefault("runs", 0)
st.title("AttackPath: a graph-powered security triage agent")
st.caption("FalkorDB finds the attack routes. NVIDIA Nemotron chooses the "
           "tools, applies the fix plan and explains it.")
tab_demo, tab_own = st.tabs(["Guided demo (simulated)",
                             "Analyze your own network"])
with tab_demo:
    workspace("demo")
with tab_own:
    workspace("own")
