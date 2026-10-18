# AttackPath: a graph-powered security triage agent

Track: Agents That Act on Connected Data (Graph Hacks: Context for AI Agents)

Live demo: graph-agent.streamlit.app
Demo video: VIDEOLINK

## What it does
AttackPath finds every route an attacker could use to reach a company's most important system, picks the single fix that closes the most routes, applies it, and proves the result by searching again. FalkorDB holds the network as a graph and answers every question about it. NVIDIA Nemotron ULTRA 3 decides which tool to use next and writes the report. The demo network is simulated.

## Why a graph
Attack routes are multi-hop paths through connected computers, accounts and weaknesses. A graph query follows those connections directly, and the agent can explain every decision with the exact route behind it.

## Graph model
Nodes: Internet, Asset (name, type, criticality), Vulnerability (id, severity, fixed), Fix (action), Decision (reason, time).
Relationships: Internet EXPOSES Asset; Asset CONNECTS_TO Asset; Asset HAS_VULN Vulnerability; Fix REMEDIATES Vulnerability; Decision APPLIED Fix.

## How the agent works
1. find_routes lists every open attack route to the target.
2. find_chokepoints counts how many open routes pass through each computer.
3. compare_fixes simulates every fix and counts the routes it closes.
4. apply_fix marks the weakness as fixed and saves a Decision node with the reason in the graph.
5. find_routes runs again to verify, and Nemotron writes the report.
Nemotron picks the tools through function calling. The graph supplies all facts, so the model cannot invent routes or fixes: the tools only return what is in the graph.

## Key graph queries
Routes from the Internet to a target:

    MATCH p = (:Internet)-[:EXPOSES|CONNECTS_TO*1..6]->(t:Asset {name:$target})
    RETURN [n IN nodes(p) | n.name] AS route

A route is open only if every computer on the way (not the Internet, not the target) has an unfixed vulnerability. That filter runs on the results of the query above plus this one:

    MATCH (a:Asset)-[:HAS_VULN]->(v:Vulnerability)
    WHERE v.fixed IS NULL OR v.fixed = false
    RETURN a.name, v.id

Applying a fix and recording the decision:

    MATCH (f:Fix {action:$a})-[:REMEDIATES]->(v:Vulnerability)
    SET v.fixed = true
    CREATE (d:Decision {reason:$r, time:$t})-[:APPLIED]->(f)

algorithms.py also provides PageRank through FalkorDB (CALL algo.pageRank) to rank the most important targets.

## Files
build_graph.py (creates the simulated network), tools.py (routes, fix simulation), actions.py (apply fix, reset), algorithms.py (PageRank, route chokepoints), agent.py (Nemotron tool-calling loop), app.py (Streamlit page), db.py (database connection from environment settings).

## Run it yourself
    git clone https://github.com/jayanthh1524/attackpath
    cd attackpath
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Create a file named .env with these settings (never commit it):

    NVIDIA_API_KEY=your_key
    FALKORDB_HOST=localhost
    FALKORDB_PORT=6379

For a local database run FalkorDB in Docker (docker run -p 6379:6379 falkordb/falkordb:latest) or use a FalkorDB Cloud instance and add FALKORDB_USERNAME, FALKORDB_PASSWORD and FALKORDB_SSL. Then:

    python3 build_graph.py
    streamlit run app.py

## Notes
- The network in the demo is simulated. The agent recommends and simulates fixes; it never changes real systems.
- Do not upload sensitive company data to the public demo.
- AI tools (including an AI assistant) helped write parts of the code. The idea, the design decisions, the testing and the deployment are mine, and I can explain every file.

## Roadmap
Tool selection through an MCP server, importing your own network from a CSV file, and weighing fixes by effort and downtime.
