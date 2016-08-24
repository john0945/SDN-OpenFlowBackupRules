
import logging

from ryu.base import app_manager
from ryu.controller import handler
from ryu.topology import event
from ryu.topology import switches
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from collections import namedtuple
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib import mac, hub
import networkx as nx

from datetime import datetime, timedelta

import pprint
pp = pprint.PrettyPrinter()

LOG = logging.getLogger(__name__)



class sr_switch():

    def __init__(self, SID):
        self.SID = SID
        self.neighbours = {}   # port : neighbour
        self.groups = {}       # SID : group ID
        self.p = []
        self.p_ex = []
        self.q = []

    #use the port as the key, since it will be unique for this switch - neighbour might be connected with two links/ports
    def add_neighbours(self, port, new_neigh):
        self.neighbours[port] = new_neigh

    def has_neighbour(self, SID):
        if SID in self.neighbours.values():
            return True
        else:
            return False

    def get_port(self, SID):
        if self.has_neighbour(SID):
            return [port for port,neigh in self.neighbours.items() if neigh == SID]
        else:
            return '-1'

    def add_group(self, SID, group):
        self.groups[SID] = group


    def handle_fw(self, paths, switch):
        for d in paths:
            if len(paths[d]) > 1:
                src = self.SID
                dst = paths[d][-1]
                next_hop = paths[d][1]
                dp = switch.dp
                ofp = dp.ofproto
                parser = dp.ofproto_parser

                group_id = src*100 + dst # src*2**16 + dst #variabilize group ids based on end destination
                self.add_group(dst, group_id)

                LOG.warn("\t\tTell switch %d to create fast failover group 0x%x with buckets:"%(src, group_id))

                port = self.get_port(next_hop)

                if len(port) > 1:
                    LOG.warn("multiple links to the same destination not yet supported. Usining first link only")

                port = port[0]
                if next_hop == dst:
                    buckets = [parser.OFPBucket(watch_port=port, actions=[parser.OFPActionPopMpls(), parser.OFPActionOutput(port)])]
                else:
                    buckets = [parser.OFPBucket(watch_port=port, actions=[parser.OFPActionOutput(port)])]

                LOG.warn("\t\t\tswitch %d over port %d"%(src, port))

                req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)
                LOG.debug(req)
                dp.send_msg(req)
