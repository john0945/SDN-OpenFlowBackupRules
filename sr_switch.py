
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
        self.groups = {}       # SID : group ID
        self.p = []
        self.p_ex = []
        self.q = []
        self.stack_groups = defaultdict(dict, {})
        self.group_counter = 100 #starting with 100 so grouos don't get confused as ports in the output part of stack_groups

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


    def handle_fw(self, paths, labels, next_hops, n_labels, n_next_hops, switch):
        for d in paths:
            if len(paths[d]) > 1:
                src = self.SID
                dst = paths[d][-1]
                next_hop = paths[d][1]
                dp = switch.dp
                ofp = dp.ofproto
                parser = dp.ofproto_parser

                group_id = src*1000 + dst # src*2**16 + dst #variabilize group ids based on end destination
                n_group_id =  src*1000 + 100 + dst
                self.add_group(dst, group_id)

                LOG.warn("\t\tTell switch %d to create fast failover group 0x%x with buckets:"%(src, group_id))

                port = self.get_port(next_hop)

                if len(port) > 1:
                    LOG.warn("multiple links to the same destination not yet supported. Usining first link only")

                port = port[0]
                if next_hop == dst:
                    #if self.SID != 2:
                    buckets = [parser.OFPBucket(watch_port=port, actions=[parser.OFPActionPopMpls(ethertype=0x8847),
                                                                          parser.NXActionRegLoad(ofs_nbits=nicira_ext.ofs_nbits(0, 31), dst="in_port",value=0),
                                                                          parser.OFPActionOutput(port)])]
                    # n_buckets = [parser.OFPBucket(watch_port=port, actions=[parser.OFPActionPopMpls(ethertype=0x8847), parser.OFPActionSetField(mpls_tc = 2), parser.OFPActionOutput(port)])]
                    n_buckets = buckets[:]

                    #else:
                     #   buckets = []
                else:
                    buckets = [parser.OFPBucket(watch_port=port, actions=[parser.NXActionRegLoad(ofs_nbits=nicira_ext.ofs_nbits(0, 31), dst="in_port",value=0),
                                                                          parser.OFPActionOutput(port)])]
                    n_buckets = buckets[:]


                #if the neighbour opposite to the failed link is in the label stack, node protection will never work, so rather use the node protection
                if next_hop not in labels[d]:
                    buckets.append(self.back_up_buckets(labels[d], next_hops[d], parser, ofp, next_hop))
                else:
                    LOG.warn("caught a label stack pointing to a potentially dead node")
                    buckets.append(self.back_up_buckets(n_labels[d], n_next_hops[d], parser, ofp, next_hop))

                if d != next_hop:
                    n_buckets.append(self.back_up_buckets(n_labels[d], n_next_hops[d], parser, ofp, next_hop))

                LOG.warn("\t\t\tswitch %d over port %d"%(src, port))

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



    def back_up_buckets(self, lb, nexthop, parser, ofp, next_hop):



        port = self.get_port(nexthop)[0]
        acts = []
        lb.reverse()

        #ofproto_v1_3.nicira_ext.NXM_OF_IN_PORT
        #acts.append(parser.OFPActionExperimenter(NXActionRegLoad())) #((ofs_nbits=2, dst="NXM_OF_IN_PORT", value=0)))
        # acts += [parser.NXActionRegLoad(ofs_nbits=283, dst="NXM_OF_IN_PORT", value=0)]
        acts += [parser.NXActionRegLoad(
            ofs_nbits=nicira_ext.ofs_nbits(0,31),
           # start=0, end =31,
            dst="in_port",
            value=0)]
        for i in lb:
            acts.append(parser.OFPActionPushMpls())
            acts.append(parser.OFPActionSetField(mpls_label= i + 15000))

        acts.append(parser.OFPActionSetField(mpls_tc = 2))
        acts.append(parser.OFPActionOutput(port))

        bucket = parser.OFPBucket(watch_port=port, actions=acts)
        return bucket

    def get_stack_group(self, label, output):
        if (label, output) in self.stack_groups.keys():
            return self.stack_groups[(label, output)]
        else:
            self.group_counter += 1
            self.stack_groups[(label, output)] = self.group_counter
            return self.group_counter


