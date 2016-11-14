
import logging

from ryu.base import app_manager
from ryu.controller import handler
from ryu.topology import event
from ryu.topology import switches
from ryu.ofproto import ofproto_v1_3, nx_actions
from ryu.ofproto import nicira_ext
from ryu.controller import ofp_event
from collections import namedtuple
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib import mac, hub
import networkx as nx

from collections import defaultdict

from datetime import datetime, timedelta

import pprint
pp = pprint.PrettyPrinter()

LOG = logging.getLogger(__name__)

class sr_switch():
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, SID):
        self.SID = SID
        self.neighbours = {}   # port : neighbour
        self.groups =[]      # SID : group ID
        self.logical_port = {}


    #use the port as the key, since it will be unique for this switch - neighbour might be connected with two links/ports
    def add_neighbours(self, port, new_neigh):
        # if the neighbour is already a neighbour, then this new link is an aggregate link
        is_agg = self.has_neighbour(new_neigh)

        self.neighbours[port] = new_neigh
        return is_agg


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

    # def add_group(self, SID, group):
    #     self.groups[SID] = group

    def create_aggregate_group(self, ports, next_hop):

        self.groups.append(next_hop)
        dp = self.dp
        ofp = self.ofp
        parser = self.parser

        buckets = []
        for p in ports:
            buckets.append(parser.OFPBucket(weight= 1, watch_port=p, actions=[parser.OFPActionOutput(p)]))

        req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_SELECT, group_id= next_hop, buckets=buckets)
        LOG.debug(req)
        dp.send_msg(req)


    def get_buckets(self, next_hop, actions=[]):

        port = self.get_port(next_hop)

        if len(port) > 1:
            #LOG.warn("multiple links to the same destination not yet supported. Usining first link only")

            if next_hop not in self.groups:
                self.create_aggregate_group(port,next_hop)

            actions.append(self.parser.NXActionRegLoad(ofs_nbits=nicira_ext.ofs_nbits(0, 31), dst="in_port", value=0))
            actions.append(self.parser.OFPActionGroup(next_hop))
            return self.parser.OFPBucket(watch_group=next_hop, actions=actions)

        else:
            port = port[0]
            actions.append(self.parser.NXActionRegLoad(ofs_nbits=nicira_ext.ofs_nbits(0, 31), dst="in_port",value=0))
            actions.append(self.parser.OFPActionOutput(port))
            return self.parser.OFPBucket(watch_port=port, actions=actions)


    def handle_fw(self, paths, labels, next_hops, n_labels, n_next_hops, switch):

        src = self.SID
        self.dp = switch.dp
        self.ofp = self.dp.ofproto
        self.parser = self.dp.ofproto_parser

        dp = self.dp
        ofp = self.ofp
        parser = self.parser


        for d in paths:
            if len(paths[d]) > 1:

                dst = paths[d][-1]
                next_hop = paths[d][1]


                group_id = src*1000 + dst # src*2**16 + dst #variabilize group ids based on end destination
                n_group_id =  src*1000 + 100 + dst
                # self.add_group(dst, group_id)

                LOG.warn("\t\tTell switch %d to create fast failover group 0x%x with buckets:"%(src, group_id))

                actions = []
                if next_hop == dst:
                    actions = [parser.OFPActionPopMpls(ethertype=0x8847)]
                buckets = [self.get_buckets(next_hop, actions)]
                n_buckets = buckets[:]

                #if the neighbour opposite to the failed link is in the label stack, node protection will never work, so rather use the node protection
                if next_hop not in labels[d]:
                    buckets.append(self.back_up_buckets(labels[d], next_hops[d], next_hop))
                else:
                    LOG.warn("caught a label stack pointing to a potentially dead node")
                    buckets.append(self.back_up_buckets(n_labels[d], n_next_hops[d], next_hop))

                if d != next_hop:
                    n_buckets.append(self.back_up_buckets(n_labels[d], n_next_hops[d], next_hop))

                # LOG.warn("\t\t\tswitch %d over port %d"%(src, port))

                req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)
                LOG.debug(req)
                dp.send_msg(req)

                req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_FF, group_id=n_group_id, buckets=n_buckets)
                LOG.debug(req)
                dp.send_msg(req)

                # install the corresponding flow rule
                match = parser.OFPMatch(eth_type=0x8847, mpls_label=dst + 15000, mpls_tc = 1)
                _match = parser.OFPMatch(**dict(match.items()))
                actions = [parser.OFPActionGroup(group_id)]
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst, priority=1000)
                LOG.debug(req)
                dp.send_msg(req)

                n_match = parser.OFPMatch(eth_type=0x8847, mpls_label=dst + 15000, mpls_tc = 2)
                _n_match = parser.OFPMatch(**dict(n_match.items()))
                n_actions = [parser.OFPActionGroup(n_group_id)]
                n_inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, n_actions)]
                n_req = parser.OFPFlowMod(datapath=dp, match=_n_match, instructions=n_inst, priority=1001)
                LOG.debug(n_req)
                dp.send_msg(n_req)


    def back_up_buckets(self, lb, nexthop, next_hop):

        acts = []
        lb.reverse()

        for i in lb:
            acts.append(self.parser.OFPActionPushMpls())
            acts.append(self.parser.OFPActionSetField(mpls_label= i + 15000))

        acts.append(self.parser.OFPActionSetField(mpls_tc = 2))

        bucket = self.get_buckets(nexthop, actions=acts)

        return bucket



#
# acts += [parser.NXActionRegLoad(
#     ofs_nbits=nicira_ext.ofs_nbits(0, 31),
#     # start=0, end =31,
#     dst="in_port",
#     value=0)]