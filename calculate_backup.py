import networkx as nx
import forwarding
from collections import defaultdict

def calculate_backup(G):

    # Create forwarding-matrix

    #fw = nx.all_pairs_dijkstra_path(G)
    #fw = nx.all_pairs_bellman_ford_path(G)
    fw, fw_lengths = forwarding.forwarding(G)

    #succ, dist = nx.floyd_warshall_successor_and_distance(G)
    # print succ

    # fw = defaultdict(dict, fw)
    # dist = defaultdict(dict, dist)
    link_fw = defaultdict(dict, {})
    node_fw = defaultdict(dict, {})
    l_lengths = defaultdict(dict, {})
    n_lengths = defaultdict(dict, {})

    node_p_dst = defaultdict(dict, {})
    # For memory overhead, we should try to make a more shallow copy that only stores the one edge that gets removed from the original
    # G_copy = G.copy(with_data=False) !!!! Refuses to copy weights

    if G.is_directed():
        G_copy_l = nx.DiGraph(G)
        G_copy_n  = nx.DiGraph(G)
    else:
        G_copy_l = nx.Graph(G)
        G_copy_n = nx.Graph(G)


    for u in G.nodes():
        for v in G.neighbors(u):
            # print "Removing edge %s-%s"%(u,v)
            G_copy_l.remove_edge(u, v)
            G_copy_n.remove_node(v)

            #pred, _dist = nx.bellman_ford_predecessor_and_distance(G_copy, u)
            fw[u][u] =[0,0]
            dst_affected = [n for n in G if fw[u][n][1] == v]
            del fw[u][u]

            _pred, _dist = nx.bellman_ford_predecessor_and_distance(G_copy_n, u)

            # print dst_affected
            node_p_dst[u][v] = []

            for n in dst_affected:
                l_lengths[u][n], link_fw[u][n] = nx.bidirectional_dijkstra(G_copy_l,u,n)
                if v in link_fw[u][n][:-1]:
                    node_p_dst[u][v] += [n]

                if n in _dist:  # Check if node is reachable at all through another path
                    n_lengths[u][n], node_fw[u][n] = nx.bidirectional_dijkstra(G_copy_n, u, n)
                else:
                    print("unreachable node %s from %s"%(n, u))

            # Restore the copy
            G_copy_l.add_edge(u, v, G[u][v])
            G_copy_n.add_node(v, G.node[v])
            G_copy_n.add_edges_from([(_u, _v, _data) for (_u, _v, _data) in G.edges(data=True) if _u == v or _v == v])

    # for u in G.nodes():
    #     for v in G.neighbors(u):
    #
    #         # print "Removing node %s"%(u,)
    #         G_copy_n.remove_node(v)
    #         fw[u][u] = [0, 0]
    #         dst_affected = [n for n in G if fw[u][n][1] == v]
    #         del fw[u][u]
    #         _pred, _dist = nx.bellman_ford_predecessor_and_distance(G_copy_n, u)
    #
    #
    #         for n in dst_affected:
    #             if n in _dist:  # Check if node is reachable at all through another path
    #                 node_fw[u][n] = nx.dijkstra_path(G_copy, u, n)
    #
    #         # Restore the copy
    #         G_copy_n.add_node(v, G.node[v])
    #         G_copy_n.add_edges_from([(_u, _v, _data) for (_u, _v, _data) in G.edges(data=True) if _u == v or _v == v])

    return fw, link_fw, node_fw, node_p_dst, fw_lengths, l_lengths, n_lengths