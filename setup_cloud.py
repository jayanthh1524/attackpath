import getpass, subprocess, sys
from falkordb import FalkorDB

host = input("Host: ").strip()
port = int(input("Port: ").strip())
user = input("Username (blank if none): ").strip() or None
pw = getpass.getpass("Password (hidden): ")

ok = None
for ssl in (False, True):
    try:
        db = FalkorDB(host=host, port=port, username=user, password=pw, ssl=ssl)
        db.list_graphs()
        ok = ssl
        break
    except Exception as e:
        print("ssl =", ssl, "failed:", str(e)[:80])
if ok is None:
    sys.exit("Could not connect. Check the details.")

keep = [l for l in open('.env').read().splitlines()
        if not l.startswith('FALKORDB_')]
keep += [f"FALKORDB_HOST={host}", f"FALKORDB_PORT={port}",
         f"FALKORDB_USERNAME={user or ''}", f"FALKORDB_PASSWORD={pw}",
         f"FALKORDB_SSL={'true' if ok else 'false'}"]
open('.env', 'w').write("\n".join(keep) + "\n")
print("Connected (ssl =", ok, "). Saved to .env. Building graph...")
subprocess.run([sys.executable, 'build_graph.py'])
