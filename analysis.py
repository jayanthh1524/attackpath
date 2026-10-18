import contextvars

from tools import all_routes, get_graph

_SET = contextvars.ContextVar('settings', default=(['Database'], False))


def use_settings(targets, fix_all=False):
    _SET.set((list(targets), fix_all))


def current_settings():
    return _SET.get()


def snapshot(targets, routes_cache=None):
    # one set of queries; everything after this runs in memory
    g = get_graph()
    vulns = {r[1]: r[0] for r in g.query(
        """MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
           WHERE v.fixed IS NULL OR v.fixed = false
           RETURN a.name, v.id""").result_set}
    fixes = {}
    for action, vid in g.query(
            """MATCH (f:Fix)-[:REMEDIATES]->(v:Vulnerability)
               WHERE v.fixed IS NULL OR v.fixed = false
               RETURN f.action, v.id""").result_set:
        fixes.setdefault(action, set()).add(vid)
    routes = (routes_cache if routes_cache is not None
              else {t: all_routes(g, t) for t in targets})
    return {'vulns': vulns, 'fixes': fixes, 'routes': routes}


def open_routes(snap, ids=None):
    # a route is open if every computer on the way has an open weakness
    ids = set(snap['vulns']) if ids is None else ids
    weak = {snap['vulns'][i] for i in ids if i in snap['vulns']}
    out = []
    for rs in snap['routes'].values():
        out += [r for r in rs if all(a in weak for a in r[1:-1])]
    return out


def fix_table(snap):
    base = len(open_routes(snap))
    rows = []
    for action, fx in snap['fixes'].items():
        left = len(open_routes(snap, set(snap['vulns']) - fx))
        rows.append((action, base - left, left))
    return sorted(rows, key=lambda r: -r[1])


def plan(snap, fix_all=False):
    # greedy: apply the fix that closes the most routes, recount, repeat
    ids = set(snap['vulns'])
    remaining = dict(snap['fixes'])
    left = open_routes(snap, ids)
    steps = []
    while left and remaining:
        best = None
        for action, fx in remaining.items():
            n = len(left) - len(open_routes(snap, ids - fx))
            if best is None or n > best[1]:
                best = (action, n)
        if best[1] <= 0:
            break
        action, n = best
        ids -= remaining.pop(action)
        left = open_routes(snap, ids)
        steps.append({'fix': action, 'closes': n, 'routes_left': len(left)})
    if fix_all:
        for action in list(remaining):
            ids -= remaining.pop(action)
            steps.append({'fix': action, 'closes': 0, 'routes_left': len(left)})
    left = open_routes(snap, ids)
    rest = [f"{snap['vulns'][i]}: {i}" for i in sorted(ids)]
    return steps, left, rest
