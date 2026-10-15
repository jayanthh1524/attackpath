from datetime import datetime
from tools import get_graph, find_attack_paths, best_fix


def apply_fix(fix_action, reason):
    # mark the weakness as fixed and record the decision in the graph
    g = get_graph()
    g.query("""MATCH (f:Fix {action:$a})-[:REMEDIATES]->(v:Vulnerability)
               SET v.fixed = true
               CREATE (d:Decision {reason:$r, time:$t})-[:APPLIED]->(f)""",
            params={'a': fix_action, 'r': reason,
                    't': datetime.now().isoformat(timespec='seconds')})


def reset_demo():
    # put everything back so we can run the demo again
    g = get_graph()
    g.query("MATCH (v:Vulnerability) SET v.fixed = false")
    g.query("MATCH (d:Decision) DETACH DELETE d")


if __name__ == '__main__':
    reset_demo()
    before = find_attack_paths()
    print(f"BEFORE: {len(before)} open routes")
    fix, closed = best_fix()
    apply_fix(fix, f"Closes {closed} of {len(before)} open routes to the Database")
    after = find_attack_paths()
    print(f"Applied fix: {fix}")
    print(f"AFTER: {len(after)} open routes")
    for r in after:
        print('   ' + ' -> '.join(r))
