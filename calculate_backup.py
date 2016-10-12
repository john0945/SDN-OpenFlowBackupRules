import networkx as nx
from collections import defaultdict

def calculate_backup(G):

    # Create forwarding-matrix
    fw = nx.all_pairs_dijkstra_path(G)

    succ, dist = nx.floyd_warshall_successor_and_distance(G)

    # print succ

    succ = defaultdict(dict, succ)
    dist = defaultdict(dict, dist)
    link_fw = defaultdict(dict, {})

    # For memory overhead, we should try to make a more shallow copy that only stores the one edge that gets removed from the original
    # G_copy = G.copy(with_data=False) !!!! Refuses to copy weights

    if G.is_directed():
        G_copy = nx.DiGraph(G)
    else:
        G_copy = nx.Graph(G)


    for u in G.nodes():
        for v in G.neighbors(u):
            # print "Removing edge %s-%s"%(u,v)
            G_copy.remove_edge(u, v)

            #pred, _dist = nx.bellman_ford_predecessor_and_distance(G_copy, u)

            dst_affected = [n for n in G if succ[u][n] == v]
            # print dst_affected
            for n in dst_affected:
                link_fw[(u, v)][n] = nx.dijkstra_path(G_copy,u,n)

            # Restore the copy
            G_copy.add_edge(u, v, G[u][v])

    for u in G.nodes():
        for v in G.neighbors(u):

            # print "Removing node %s"%(u,)
            G_copy.remove_node(v)

            _pred, _dist = nx.bellman_ford_predecessor_and_distance(G_copy, u)
            dst_affected = [n for n in succ[u] if succ[u][n] == v]
            # print dst_affected

            for n in dst_affected:
                if n in _dist:  # Check if node is reachable at all through another path
                    dist[(u, v)][n] = _dist[n]

            # Restore the copy
            G_copy.add_node(v, G.node[v])
            G_copy.add_edges_from([(_u, _v, _data) for (_u, _v, _data) in G.edges(data=True) if _u == v or _v == v])

    return fw, link_fw, dict(succ)