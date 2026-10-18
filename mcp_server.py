import uuid

from mcp.server.fastmcp import FastMCP

from actions import apply_fix
from analysis import fix_table, open_routes, plan, snapshot
from db import connect
from loader import DEMO, load_network, parse_csv
from tools import use_graph

mcp = FastMCP("stratum")


def _load(network, targets):
    # network = demo, startup, office, or the CSV text itself
    if network == "demo":
        net = DEMO
    else:
        if network in ("startup", "office"):
            network = open(f"samples/{network}.csv").read()
        net, errors = parse_csv(network)
        if errors:
            raise ValueError("; ".join(errors))
    bad = [t for t in targets if t not in net["assets"]]
    if bad:
        raise ValueError(f"Unknown systems: {bad}. Choose from {net['assets']}")
    name = "s_m" + uuid.uuid4().hex[:8]
    load_network(name, net)
    use_graph(name)
    return name


def _drop(name):
    try:
        connect().select_graph(name).delete()
    except Exception:
        pass


@mcp.tool()
def list_sample_networks() -> list[str]:
    """Sample networks you can analyze: demo, startup, office."""
    return ["demo", "startup", "office"]


@mcp.tool()
def investigate_network(network: str, targets: list[str]) -> dict:
    """Find the open attack routes to the targets, the chokepoints, and compare
    every fix. network is a sample name (demo, startup, office) or CSV text with
    columns kind,name,target,id,severity,fix. targets are the valuable systems."""
    name = _load(network, targets)
    try:
        snap = snapshot(targets)
        routes = open_routes(snap)
        counts = {}
        for r in routes:
            for n in r[1:-1]:
                counts[n] = counts.get(n, 0) + 1
        return {"open_routes": [" -> ".join(r) for r in routes],
                "chokepoints": sorted(counts.items(), key=lambda x: -x[1]),
                "fix_comparison": [
                    {"fix": f, "routes_closed": c, "routes_left": l}
                    for f, c, l in fix_table(snap)]}
    finally:
        _drop(name)


@mcp.tool()
def remediate_network(network: str, targets: list[str],
                      fix_all: bool = False) -> dict:
    """Build and apply a fix plan (best fix first, recount, repeat) in a
    temporary graph and return the routes before and after."""
    name = _load(network, targets)
    try:
        snap = snapshot(targets)
        before = open_routes(snap)
        steps, left, rest = plan(snap, fix_all)
        for s in steps:
            apply_fix(s["fix"], f"Closes {s['closes']} open routes to "
                      f"{', '.join(targets)}; {s['routes_left']} left")
        return {"routes_before": len(before), "routes_after": len(left),
                "fixes_applied_in_order": steps,
                "remaining_routes": [" -> ".join(r) for r in left],
                "weaknesses_still_open": rest}
    finally:
        _drop(name)


if __name__ == "__main__":
    mcp.run()
