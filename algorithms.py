from tools import get_graph, find_attack_paths

TIMEOUT = 30000  # milliseconds


def rank_importance():
    # PageRank: which computers are the most important targets
    g = get_graph()
    res = g.query("""CALL algo.pageRank('Asset', 'CONNECTS_TO')
                     YIELD node, score
                     RETURN node.name AS name, score
                     ORDER BY score DESC""", timeout=TIMEOUT)
    return [(row[0], row[1]) for row in res.result_set]


def rank_chokepoints():
    # Betweenness: which computers sit on the most shortest routes
    g = get_graph()
    res = g.query("""CALL algo.betweenness({
                         nodeLabels: ['Internet', 'Asset'],
                         relationshipTypes: ['EXPOSES', 'CONNECTS_TO']})
                     YIELD node, score
                     RETURN node.name AS name, score
                     ORDER BY score DESC""", timeout=TIMEOUT)
    return [(row[0], row[1]) for row in res.result_set]


def route_chokepoints(target='Database'):
    # count how many OPEN attack routes pass through each computer
    counts = {}
    for route in find_attack_paths(target):
        for name in route[1:-1]:
            counts[name] = counts.get(name, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


if __name__ == '__main__':
    print('ROUTE CHOKEPOINTS (open routes through each computer)')
    for name, n in route_chokepoints():
        print(f'   {name}: {n}')

    for title, func in [('MOST IMPORTANT TARGETS (PageRank)', rank_importance),
                        ('BIGGEST CHOKEPOINTS (Betweenness)', rank_chokepoints)]:
        print(title)
        try:
            for name, score in func()[:5]:
                print(f'   {name}: {score:.3f}')
        except Exception as e:
            print('   (this algorithm failed:', str(e)[:60], ')')
