from falkordb import FalkorDB


def get_graph():
    db = FalkorDB(host='localhost', port=6379)
    return db.select_graph('attackpath')


def open_vulns(g):
    # every computer that still has an unfixed weakness
    res = g.query("""MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
                     WHERE v.fixed IS NULL OR v.fixed = false
                     RETURN a.name, v.id""")
    return [(row[0], row[1]) for row in res.result_set]


def all_routes(g, target):
    # every possible path from the Internet to the target
    res = g.query("""MATCH p = (:Internet)-[:EXPOSES|CONNECTS_TO*1..6]->(t:Asset {name:$target})
                     RETURN [n IN nodes(p) | n.name] AS route""",
                  params={'target': target})
    return [row[0] for row in res.result_set]


def open_routes(g, target, vulnerable_assets):
    # keep a route only if every computer on the way (not the Internet,
    # not the target) has an open weakness
    return [r for r in all_routes(g, target)
            if all(a in vulnerable_assets for a in r[1:-1])]


def find_attack_paths(target='Database'):
    g = get_graph()
    vulnerable = {a for a, vid in open_vulns(g)}
    return open_routes(g, target, vulnerable)


def list_fixes():
    g = get_graph()
    res = g.query("MATCH (f:Fix) RETURN f.action")
    return [row[0] for row in res.result_set]


def simulate_fix(fix_action, target='Database'):
    # pretend we applied the fix, and compare the routes before and after
    g = get_graph()
    res = g.query("""MATCH (f:Fix {action:$a})-[:REMEDIATES]->(v:Vulnerability)
                     RETURN v.id""", params={'a': fix_action})
    fixed_ids = {row[0] for row in res.result_set}
    vulns = open_vulns(g)
    before = open_routes(g, target, {a for a, vid in vulns})
    after = open_routes(g, target, {a for a, vid in vulns if vid not in fixed_ids})
    return before, after


def best_fix(target='Database'):
    # try every fix and pick the one that closes the most routes
    best = None
    for fix in list_fixes():
        before, after = simulate_fix(fix, target)
        closed = len(before) - len(after)
        if best is None or closed > best[1]:
            best = (fix, closed)
    return best


if __name__ == '__main__':
    routes = find_attack_paths()
    print(f"Open attack routes to the Database: {len(routes)}")
    for r in routes:
        print('   ' + ' -> '.join(r))
    fix, closed = best_fix()
    print(f"Best fix: {fix} (closes {closed} routes)")
    before, after = simulate_fix(fix)
    print(f"Before: {len(before)} routes.  After: {len(after)} routes.")
