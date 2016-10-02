# -*- coding: utf-8 -*-
"""Disjoint paths using path-removal and Dijkstra's algorithm.
"""

#    Copyright (C) 2015-2016 by
#    Niels L. M. van Adrichem <n.l.m.vanadrichem@tudelft.nl>
#    All rights reserved.
#    BSD license.

__author__ = """\n""".join(['Niels L. M. van Adrichem <n.l.m.vanadrichem@tudelft.nl>'])
__all__ = ['extended_disjoint']

import networkx as nx
from collections import defaultdict

def extended_disjoint(G, weight=None, node_disjoint=False, edge_then_node_disjoint=False):
    if node_disjoint == True and edge_then_node_disjoint == True:
        raise nx.NetworkXUnfeasible("Edge-then-node disjointness overrides node disjointness")
        
        
    if G.is_multigraph():
        raise nx.NetworkXUnfeasible(
            "Apply link-splitting before calling this algorithm to allow multigraphs. Note that multigraphs are not useful when searching for guaranteed node disjointness, a graph containing the minimum-weight edges suffices.")
        
    if weight == None:
        weight = "_weight"
        while any( weight in d for u, v, d in G.edges(data = True) ):
            weight = "_"+weight
    
    succ,dist = nx.floyd_warshall_successor_and_distance(G, weight=weight)
    
    #print succ
    
    succ = defaultdict(dict, succ)
    dist = defaultdict(dict, dist)
    notFirst = set()
    #Create forwarding-matrix

    #For memory overhead, we should try to make a more shallow copy that only stores the one edge that gets removed from the original
    #G_copy = G.copy(with_data=False) !!!! Refuses to copy weights
    if G.is_directed():
        G_copy = nx.DiGraph(G)
    else:
        G_copy = nx.Graph(G)
    
    if node_disjoint == True or edge_then_node_disjoint == True:        
        for u in G.nodes():
            for v in G.neighbors(u):
            
                #print "Removing node %s"%(u,)
                G_copy.remove_node(v)
                
                _pred,_dist = nx.bellman_ford_predecessor_and_distance(G_copy, u, weight=weight)
                dst_affected = [n for n in succ[u] if succ[u][n] == v]
                #print dst_affected
                
                for n in dst_affected:
                    if n in _dist: #Check if node is reachable at all through another path
                        dist[(u, v)][n] = _dist[n]
                        next = n
                        different_successor = False
                        while next != u:                            
                            prev = _pred[next][0]
                            #Ignore if successive path is guaranteed equal to the regular shortest path
                            if different_successor == True or succ[prev][n] != next:
                                different_successor = True
                                
                                succ[(prev,v)][n] = next

                                if u != prev:
                                    notFirst.add( ((prev,v),n) )
              
                            next = prev
                    #else: We don't use these anyways
                    #    succ[(u,v)][n] = None
                
                #Restore the copy
                G_copy.add_node(v, G.node[v])
                G_copy.add_edges_from([(_u, _v, _data) for (_u, _v, _data) in G.edges(data=True) if _u == v or _v == v])
            
    if node_disjoint == False or edge_then_node_disjoint == True:
        for u in G.nodes():
            for v in G.neighbors(u):
                #print "Removing edge %s-%s"%(u,v)
                G_copy.remove_edge(u, v)
    
                _pred,_dist = nx.bellman_ford_predecessor_and_distance(G_copy, u, weight=weight)
                
                dst_affected = [n for n in G if succ[u][n] == v]
                #print dst_affected
                
                for n in dst_affected:
                    if n in _dist:
                        dist[(u, (u, v))][n] = _dist[n]
                        next = n
                        different_successor = False
                        while next != u:
                            prev = _pred[next][0]
                            #Ignore if successive path is guaranteed equal to the regular shortest path, exclude upgrade to node-failure in case of combined-failure detection
                            if different_successor == True or succ[prev][n] != next or (edge_then_node_disjoint is True and v == next):
                                different_successor = True                                
                                #ignore edge-disjoint forwarding rules that are equal to their node-disjoint counterparts since those can be forwarded through wildcard matching
                                if edge_then_node_disjoint is True and (prev,v) in succ and n in succ[(prev,v)] and succ[(prev,v)][n] == next:
                                    pass
                                else:
                                    succ[(prev,(u,v))][n] = next
                                    if u != prev:
                                        notFirst.add( ((prev,(u,v)),n) )
                            
                            next = prev
                    #We don't use these anyways
                    #else: # edge_then_node_disjoint == False: #If edge_then_node_disjoint == True, then succ[(u, v)][n] MUST already be None since it is stricter to find
                    #    succ[(u,(u,v))][n] = None
    
                #Restore the copy
                G_copy.add_edge(u, v, G[u][v])
    
    return dict(dist), dict(succ), notFirst