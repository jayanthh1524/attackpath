from falkordb import FalkorDB

db = FalkorDB(host='localhost', port=6379)

# start fresh every time we run this file
try:
    db.select_graph('attackpath').delete()
except Exception:
    pass
g = db.select_graph('attackpath')

# (name, type, criticality 1-5)
assets = [
    ('Web Server', 'server', 3), ('Mail Server', 'server', 2),
    ('VPN Gateway', 'network', 2), ('App Server', 'server', 4),
    ('Login Server', 'server', 4), ('Employee Laptop', 'laptop', 2),
    ('File Server', 'server', 3), ('Database', 'database', 5),
    ('Backup Server', 'server', 4), ('Admin Workstation', 'laptop', 3),
    ('Payment Server', 'server', 5),
]
for name, kind, crit in assets:
    g.query("CREATE (:Asset {name:$n, type:$t, criticality:$c})",
            params={'n': name, 't': kind, 'c': crit})

g.query("CREATE (:Internet {name:'Internet'})")

# the Internet can reach these three
for name in ['Web Server', 'Mail Server', 'VPN Gateway']:
    g.query("MATCH (i:Internet), (a:Asset {name:$n}) CREATE (i)-[:EXPOSES]->(a)",
            params={'n': name})

# who can connect to whom
links = [
    ('Web Server', 'App Server'), ('Mail Server', 'Employee Laptop'),
    ('VPN Gateway', 'Admin Workstation'), ('App Server', 'Database'),
    ('App Server', 'Login Server'), ('App Server', 'Payment Server'),
    ('Login Server', 'Database'), ('Employee Laptop', 'File Server'),
    ('Employee Laptop', 'Admin Workstation'), ('File Server', 'Backup Server'),
    ('Backup Server', 'Database'), ('Admin Workstation', 'Database'),
    ('Admin Workstation', 'Payment Server'),
]
for a, b in links:
    g.query("MATCH (x:Asset {name:$a}), (y:Asset {name:$b}) CREATE (x)-[:CONNECTS_TO]->(y)",
            params={'a': a, 'b': b})

# (asset, fake vuln id, severity, fix action)
vulns = [
    ('Web Server', 'VULN-001', 'critical', 'Update web framework'),
    ('App Server', 'VULN-002', 'high', 'Patch app server'),
    ('Admin Workstation', 'VULN-003', 'high', 'Enforce admin MFA'),
    ('Employee Laptop', 'VULN-004', 'medium', 'Install security update'),
    ('VPN Gateway', 'VULN-005', 'high', 'Upgrade VPN software'),
    ('Mail Server', 'VULN-006', 'medium', 'Block risky attachments'),
]
for asset, vid, sev, fix in vulns:
    g.query("""MATCH (a:Asset {name:$a})
               CREATE (a)-[:HAS_VULN]->(v:Vulnerability {id:$v, severity:$s})
               CREATE (f:Fix {action:$f})-[:REMEDIATES]->(v)""",
            params={'a': asset, 'v': vid, 's': sev, 'f': fix})

print('Graph built!')

# first attack-path search
res = g.query("""MATCH p = (:Internet)-[:EXPOSES|CONNECTS_TO*1..6]->(d:Asset {name:'Database'})
                 RETURN [n IN nodes(p) | n.name] AS route""")
print('Attack routes to the Database:', len(res.result_set))
for row in res.result_set:
    print(' -> '.join(row[0]))
