import csv
import io
import time

from db import connect

DEMO = {
    'assets': ['Web Server', 'Mail Server', 'VPN Gateway', 'App Server',
               'Login Server', 'Employee Laptop', 'File Server', 'Database',
               'Backup Server', 'Admin Workstation', 'Payment Server'],
    'exposed': ['Web Server', 'Mail Server', 'VPN Gateway'],
    'links': [('Web Server', 'App Server'), ('Mail Server', 'Employee Laptop'),
              ('VPN Gateway', 'Admin Workstation'), ('App Server', 'Database'),
              ('App Server', 'Login Server'), ('App Server', 'Payment Server'),
              ('Login Server', 'Database'), ('Employee Laptop', 'File Server'),
              ('Employee Laptop', 'Admin Workstation'),
              ('File Server', 'Backup Server'), ('Backup Server', 'Database'),
              ('Admin Workstation', 'Database'),
              ('Admin Workstation', 'Payment Server')],
    'vulns': [('Web Server', 'VULN-001', 'critical', 'Update web framework'),
              ('App Server', 'VULN-002', 'high', 'Patch app server'),
              ('Admin Workstation', 'VULN-003', 'high', 'Enforce admin MFA'),
              ('Employee Laptop', 'VULN-004', 'medium', 'Install security update'),
              ('VPN Gateway', 'VULN-005', 'high', 'Upgrade VPN software'),
              ('Mail Server', 'VULN-006', 'medium', 'Block risky attachments')],
}

MAX_ASSETS, MAX_LINKS, MAX_ROWS = 25, 60, 150
COLUMNS = ['kind', 'name', 'target', 'id', 'severity', 'fix']


def to_csv(net):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(COLUMNS)
    for a in net['exposed']:
        w.writerow(['exposed', a, '', '', '', ''])
    for a, b in net['links']:
        w.writerow(['connection', a, b, '', '', ''])
    for a, i, s, f in net['vulns']:
        w.writerow(['weakness', a, '', i, s, f])
    return out.getvalue()


def clean(s):
    return (s or '').strip().replace('"', "'").replace('\\', '')[:60]


def parse_csv(text):
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows or not set(COLUMNS).issubset(rows[0].keys()):
        return None, ['The file needs these columns: ' + ','.join(COLUMNS)]
    if len(rows) > MAX_ROWS:
        return None, [f'Too many rows (max {MAX_ROWS}).']
    errors, assets, exposed, links, vulns = [], [], [], [], []

    def add(name):
        if name.lower() == 'internet':
            errors.append('"Internet" is a reserved name.')
        elif name not in assets:
            assets.append(name)

    for n, r in enumerate(rows, start=2):
        kind, name = clean(r['kind']).lower(), clean(r['name'])
        if not name:
            errors.append(f'Row {n}: name is empty.')
        elif kind == 'exposed':
            exposed.append(name)
            add(name)
        elif kind == 'connection':
            tgt = clean(r['target'])
            if not tgt:
                errors.append(f'Row {n}: a connection needs a target.')
            else:
                links.append((name, tgt))
                add(name)
                add(tgt)
        elif kind == 'weakness':
            vid, fix = clean(r['id']), clean(r['fix'])
            if not vid or not fix:
                errors.append(f'Row {n}: a weakness needs an id and a fix.')
            else:
                vulns.append((name, vid, clean(r['severity']) or 'unknown', fix))
                add(name)
        else:
            errors.append(f'Row {n}: kind must be exposed, connection or weakness.')
    if len({v[1] for v in vulns}) != len(vulns):
        errors.append('Weakness ids must be unique.')
    if not exposed:
        errors.append('Add at least one "exposed" row (reachable from the Internet).')
    if not vulns:
        errors.append('Add at least one "weakness" row.')
    if len(assets) > MAX_ASSETS:
        errors.append(f'Too many computers (max {MAX_ASSETS}).')
    if len(links) > MAX_LINKS:
        errors.append(f'Too many connections (max {MAX_LINKS}).')
    if errors:
        return None, errors[:8]
    return {'assets': assets, 'exposed': list(dict.fromkeys(exposed)),
            'links': list(dict.fromkeys(links)), 'vulns': vulns}, []


def cleanup(db, keep, cap=15):
    # keeps the free database tidy: old visitor graphs are deleted
    try:
        names = [n.decode() if isinstance(n, bytes) else n
                 for n in db.list_graphs()]
        old = [n for n in names if n.startswith('s_') and n != keep]
        for n in old[:max(0, len(old) - cap)]:
            db.select_graph(n).delete()
    except Exception:
        pass


def load_network(name, net):
    db = connect()
    try:
        db.select_graph(name).delete()
    except Exception:
        pass
    g = db.select_graph(name)
    g.query("CREATE (:Internet {name:'Internet'})")
    g.query("UNWIND $rows AS r CREATE (:Asset {name:r.name})",
            params={'rows': [{'name': a} for a in net['assets']]})
    g.query("""UNWIND $rows AS r
               MATCH (i:Internet), (a:Asset {name:r.name})
               CREATE (i)-[:EXPOSES]->(a)""",
            params={'rows': [{'name': a} for a in net['exposed']]})
    g.query("""UNWIND $rows AS r
               MATCH (a:Asset {name:r.a}), (b:Asset {name:r.b})
               CREATE (a)-[:CONNECTS_TO]->(b)""",
            params={'rows': [{'a': a, 'b': b} for a, b in net['links']]})
    g.query("""UNWIND $rows AS r
               MATCH (a:Asset {name:r.asset})
               CREATE (a)-[:HAS_VULN]->(v:Vulnerability
                      {id:r.id, severity:r.sev, fixed:false})
               MERGE (f:Fix {action:r.fix})
               CREATE (f)-[:REMEDIATES]->(v)""",
            params={'rows': [{'asset': a, 'id': i, 'sev': s, 'fix': f}
                             for a, i, s, f in net['vulns']]})
    cleanup(db, name)


_runs = []


def allow_run(per_hour=40):
    # protects the AI quota: at most 40 agent runs per hour for everyone
    now = time.time()
    _runs[:] = [t for t in _runs if now - t < 3600]
    if len(_runs) >= per_hour:
        return False
    _runs.append(now)
    return True

