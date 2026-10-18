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

st.set_page_config(page_title="Stratum", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 1.2rem; max-width: 1250px;}
footer {visibility: hidden;}
.hero {background: linear-gradient(135deg,#0f2a3d,#123c4a); border: 1px solid #1f4b5c;
       border-radius: 14px; padding: 18px 22px; margin-bottom: 14px;}
.hero h1 {margin: 0; font-size: 1.7rem;}
.hero p {margin: 4px 0 0 0; color: #a9b8c9;}
.chip {display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .78rem;
       margin: 8px 6px 0 0; background: #13303f; border: 1px solid #24566b; color: #bfe3f0;}
.kpi {border-radius: 12px; padding: 12px 16px; border: 1px solid #263041; background: #151b27;}
.kpi .kl {font-size: .75rem; color: #93a1b5; text-transform: uppercase; letter-spacing: .05em;}
.kpi .kv {font-size: 1.9rem; font-weight: 700;}
.kpi.bad .kv {color: #ff6b6b;} .kpi.good .kv {color: #2dd4a7;}
.kpi.warn .kv {color: #ffb454;} .kpi.info .kv {color: #6cb6ff;}
.legend span {display: inline-block; margin-right: 16px; font-size: .82rem; color: #b6c2d3;}
.dot {display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px;}
</style>
""", unsafe_allow_html=True)


def card(col, label, value, tone="info"):
    col.markdown(f'<div class="kpi {tone}"><div class="kl">{label}</div>'
                 f'<div class="kv">{value}</div></div>', unsafe_allow_html=True)

ss = st.session_state


def graph_dot(net, routes, targets, weak):
    # drawn from the network data itself, so it needs no database queries
    hot = {(a, b) for r in routes for a, b in zip(r, r[1:])}
    lines = ['digraph G {', 'rankdir=LR;', 'bgcolor="transparent";',
             'node [shape=box, style="rounded,filled", '
             'fillcolor="#eeeeee", fontname="Helvetica"];',
             '"Internet" [fillcolor="#ffcdd2"];']
    for name in net["assets"]:
        color = ("#c8e6c9" if name in targets
                 else "#ffe0b2" if name in weak else "#eeeeee")
        lines.append(f'"{name}" [fillcolor="{color}"];')
    for a, b in [("Internet", x) for x in net["exposed"]] + list(net["links"]):
        style = ('color="red", penwidth=2.5' if (a, b) in hot
                 else 'color="#8a94a6"')
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
    L = ["# Stratum security triage report", "",
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
        st.markdown("#### Preview: how your network will be drawn")
        st.caption("This is the template network. Upload your own CSV and it "
                   "replaces this picture. Orange = a computer with an open "
                   "weakness, green = a system you protect. Red lines (the "
                   "attack routes) appear once your network is analyzed.")
        st.graphviz_chart(graph_dot(
            DEMO, [], ["Database"], {v[0] for v in DEMO["vulns"]}))
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
    st.markdown("### Network now")
    n1, n2 = st.columns([1, 3])
    card(n1, "Open attack routes", len(routes), "bad" if routes else "good")
    n2.markdown('<div class="legend"><span><i class="dot" style="background:#ff4d4d"></i>open attack route</span>'
                '<span><i class="dot" style="background:#ffe0b2"></i>computer with an open weakness</span>'
                '<span><i class="dot" style="background:#c8e6c9"></i>system you protect</span>'
                '<span><i class="dot" style="background:#ffcdd2"></i>Internet</span></div>',
                unsafe_allow_html=True)
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
        st.markdown("### Results")
        b, a = res["before_n"], res["after_n"]
        cut = round(100 * (b - a) / b) if b else 0
        try:
            applied = decisions()
        except Exception:
            applied = []
        k1, k2, k3, k4 = st.columns(4)
        card(k1, "Open routes before", b, "bad" if b else "good")
        card(k2, "Open routes after", a, "good" if a == 0 else "warn")
        card(k3, "Fixes applied", len(applied), "info")
        card(k4, "Routes closed", f"{cut}%", "good")
        st.write("")
        g1, g2 = st.columns(2)
        g1.markdown("**Before**")
        g1.graphviz_chart(res["before_dot"])
        g2.markdown("**After**")
        g2.graphviz_chart(res["after_dot"])
        if applied:
            st.markdown("### Fix plan (recorded in the graph)")
            st.dataframe([{"Step": i, "Fix": f, "Why": r}
                          for i, (f, r) in enumerate(applied, 1)],
                         hide_index=True)
        st.markdown("### Agent report")
        with st.container(border=True):
            st.markdown(res["report"])
        st.download_button("Download the full report (Markdown)", res["md"],
                           "attackpath_report.md", "text/markdown",
                           key=f"{kind}_dl")
        with st.expander("Agent steps (tool calls)"):
            st.code(res["steps"])


ss.setdefault("runs", 0)
BRAND = 'Stratum'
SPLASH = """
<style>
.splash{position:fixed;top:0;left:0;right:0;bottom:0;z-index:1000000;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at 50% 40%,#12303f 0%,#0a1220 70%);animation:splashOut .8s ease 3.9s forwards;}
.splash-inner{text-align:center;}
.splash .net{display:flex;align-items:center;justify-content:center;margin-bottom:26px;}
.splash .n{width:20px;height:20px;border-radius:50%;background:#ffe0b2;transform:scale(0);animation:pop .4s ease forwards;}
.splash .n1{background:#ffcdd2;animation-delay:.2s;}
.splash .n2{animation-delay:.6s;}
.splash .n3{animation-delay:1s;}
.splash .n4{animation:pop .4s ease 1.4s forwards,good .5s ease 2.1s forwards;}
.splash .l{width:78px;height:4px;background:#ff4d4d;transform:scaleX(0);transform-origin:left;animation:grow .4s ease forwards,heal .5s ease 2s forwards;}
.splash .l1{animation-delay:.4s,2s;}
.splash .l2{animation-delay:.8s,2s;}
.splash .l3{animation-delay:1.2s,2s;}
.splash .brand{font-size:3.2rem;font-weight:800;color:#e6eaf2;opacity:0;letter-spacing:.5em;animation:brandIn 1s ease 2.4s forwards;}
.splash .tag{margin-top:10px;color:#9fb3c8;opacity:0;animation:tagIn .8s ease 3s forwards;}
@keyframes pop{to{transform:scale(1);}}
@keyframes grow{to{transform:scaleX(1);}}
@keyframes heal{to{background:#00c2a8;box-shadow:0 0 12px #00c2a8;}}
@keyframes good{to{background:#2dd4a7;box-shadow:0 0 18px #2dd4a7;}}
@keyframes brandIn{to{opacity:1;letter-spacing:.14em;}}
@keyframes tagIn{to{opacity:.9;}}
@keyframes splashOut{to{opacity:0;visibility:hidden;}}
</style>
<div class="splash"><div class="splash-inner">
<div class="net"><i class="n n1"></i><b class="l l1"></b><i class="n n2"></i><b class="l l2"></b><i class="n n3"></i><b class="l l3"></b><i class="n n4"></i></div>
<div class="brand">BRANDNAME</div>
<div class="tag">Find the route. Close it. Prove it.</div>
</div></div>
"""
if not ss.get("splash_done"):
    ss["splash_done"] = True
    st.markdown(SPLASH.replace("BRANDNAME", BRAND), unsafe_allow_html=True)

st.markdown("""
<div class="hero">
<h1>🛡️ Stratum</h1>
<p>Graph-powered security triage agent: find how an attacker reaches what matters, then fix it in the right order.</p>
<span class="chip">FalkorDB graph</span><span class="chip">NVIDIA Nemotron agent</span><span class="chip">MCP server included</span><span class="chip">Track 1: agents that act on connected data</span>
</div>
""", unsafe_allow_html=True)
SCHEMA_DOT = """digraph S { rankdir=LR; bgcolor="transparent";
node [shape=box, style="rounded,filled", fontname="Helvetica", fillcolor="#eeeeee"];
Internet [fillcolor="#ffcdd2"]; Asset [fillcolor="#ffe0b2"]; Vulnerability [fillcolor="#e1bee7"]; Fix [fillcolor="#c8e6c9"]; Decision [fillcolor="#bbdefb"];
Internet -> Asset [label="EXPOSES"]; Asset -> Asset [label="CONNECTS_TO"]; Asset -> Vulnerability [label="HAS_VULN"]; Fix -> Vulnerability [label="REMEDIATES"]; Decision -> Fix [label="APPLIED"]; }"""
with st.expander("Graph model: how the network is stored in FalkorDB"):
    st.graphviz_chart(SCHEMA_DOT)
    st.caption("A route from the Internet to a protected system is open only if every computer on it has an unfixed weakness. Each applied fix is saved as a Decision node, so every action is traceable.")

tab_demo, tab_own = st.tabs(["Guided demo (simulated)",
                             "Analyze your own network"])
with tab_demo:
    workspace("demo")
with tab_own:
    workspace("own")
