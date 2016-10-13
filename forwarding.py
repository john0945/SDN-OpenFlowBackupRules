import itertools
import networkx as nx

from collections import defaultdict

def forwarding(G):
    pairs = list(itertools.combinations(G.node.keys(), 2))
    fw = {}
    fw = defaultdict(dict, fw) #this is necessary so that we don't get a key error when adding a new node's paths
    for i in pairs:
        length,path = nx.bidirectional_dijkstra(G, i[0], i[1])
        fw[i[0]][i[1]] = path[:] # [:] is necessary to copy list values, and not save a pointer. without [:] the path gets reversed
        path.reverse()
        fw[i[1]][i[0]] = path[:]
    return fw
