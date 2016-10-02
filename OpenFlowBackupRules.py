# Copyright (C) 2016, Delft University of Technology, Faculty of Electrical Engineering, Mathematics and Computer Science, Network Architectures and Services, Niels van Adrichem
# 
# This file is part of OpenFlowBackupRules.
# 
# OpenFlowBackupRules is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# OpenFlowBackupRules is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with OpenFlowBackupRules.  If not, see <http://www.gnu.org/licenses/>.

#Tested with OVS 2.5.0. Definitely doesn't work with 2.3.0, I think it's to do with MPLS support, or FF groups. Pinging to neighbours works, but pinging
#beyond that causes the flow table to be deleted and the controller has to get involved.

import sr_switch
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
import extended_disjoint

from datetime import datetime, timedelta

import pprint
pp = pprint.PrettyPrinter()

LOG = logging.getLogger(__name__)



class OpenFlowBackupRules(app_manager.RyuApp):
    ''' This app configures all-to-all backup rules for the discovered network.
    '''
    _CONTEXTS = {
        'switches': switches.Switches,
    }
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    

    def __init__(self, *args, **kwargs):
        super(OpenFlowBackupRules, self).__init__(*args, **kwargs)

        self.sr_switches = {}
        self.G = nx.DiGraph()
        self.mac_learning = {}
        self.IP_learning = {}
        #parameters
#        self.path_computation = "sr"

        self.path_computation = "sr"#"shortest_path"
        self.node_disjoint = False #Edge disjointness still implies crankback rules to the source. No segmenting occurs, need to confirm that the primary path will also be the shortest combination of segments.
        self.edge_then_node_disjoint = True #Only applicable to extended_disjoint
        self.number_of_disjoint_paths = 2 #Only applicable to simple_disjoint and bhandari. k>2 not well implemented for the source-node, rest should work

        self.is_active = True
        self.topology_update = None #datetime.now()
        self.forwarding_update = None
        self.threads.append( hub.spawn(self._calc_ForwardingMatrix) )

    def close(self):
        self.is_active = False
        hub.joinall( self.threads )        

    @handler.set_ev_cls(ofp_event.EventOFPStateChange,  [CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        
        dp = ev.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser        
        
        #Delete any possible currently existing flows.
        del_flows = parser.OFPFlowMod(dp, table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, command=ofp.OFPFC_DELETE) 
        dp.send_msg(del_flows)
        
        del_groups = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_DELETE, group_id=ofp.OFPG_ALL)
        dp.send_msg(del_groups)
        
        #Make sure deletion is finished using a barrier before additional flows are added
        barrier_req = parser.OFPBarrierRequest(dp)
        dp.send_msg(barrier_req)

    @handler.set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):


        LOG.warn("OpenFlowBackupRules: "+ str(ev))
        switch = ev.switch
        self.G.add_node(switch.dp.id, switch=switch)
        dp = switch.dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.sr_switches[dp.id] = sr_switch.sr_switch(dp.id)

        #Configure table-miss entry
        match = parser.OFPMatch()
        actions = [ parser.OFPActionOutput( ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER ) ]
        inst = [ parser.OFPInstructionActions( ofp.OFPIT_APPLY_ACTIONS, actions ) ]
        mod = parser.OFPFlowMod(datapath=dp, match=match, instructions=inst, priority=0) #LOWEST PRIORITY POSSIBLE
        dp.send_msg(mod)

    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        LOG.warn("OpenFlowBackupRules: "+ str(ev))
        LOG.error("OpenFlowBackupRules: To Do, fix what to do upon leaving of a switch")

#    @handler.set_ev_cls(event.EventPortAdd)
#    def port_add_handler(self, ev):
#        LOG.debug("OpenFlowBackupRules: "+ str(ev))
#
#    @handler.set_ev_cls(event.EventPortDelete)
#    def port_delete_handler(self, ev):
#        LOG.debug("OpenFlowBackupRules: "+ str(ev))
#
#    @handler.set_ev_cls(event.EventPortModify)
#    def port_modify_handler(self, ev):
#        LOG.debug("OpenFlowBackupRules: "+ str(ev))

    @handler.set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        LOG.warn("OpenFlowBackupRules: "+ str(ev))
        link = ev.link
        src = link.src
        dst = link.dst
        self.G.add_edge(src.dpid, dst.dpid, port=src.port_no, link=link)
        self.topology_update = datetime.now()

        self.sr_switches[src.dpid].add_neighbours(src.port_no, dst.dpid)
        #self.adj[src.dpid][dst.dpid] = src.port_no
        #self.switch_ports[src.dpid,src.port_no] = link
        #self._print_adj_matrix()
        #self._print_fw_matrix()

    @handler.set_ev_cls(event.EventLinkDelete)
    def link_del_handler(self, ev):
        LOG.warn("OpenFlowBackupRules: "+ str(ev))
        LOG.error("OpenFlowBackupRules: To Do, fix what to do upon deletion of a link")

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        def drop():
            LOG.error("\tImplement drop function")
            
        def flood():
            LOG.warn("\tFlooding packet")
            for (iDpid, switch) in self.G.nodes(data='switch'):

                #Initialize ports
                ports = []
                #Add local port if that is not the originating port
                #if (iDpid,ofp.OFPP_LOCAL) != (dpid, in_port):
                #    ports += [ofp.OFPP_LOCAL]

                #Exclude the inter-switch and possible other incoming ports from flooding
                ports += [p.port_no for p in switch.ports if (iDpid,p.port_no) != (dpid, in_port) and p.port_no not in [self.G.get_edge_data(iDpid, jDpid)['port'] for jDpid in self.G.neighbors(iDpid)]]

                actions = [parser.OFPActionOutput(port, 0) for port in ports]

                if iDpid == dpid and buffer_id != None:
                    LOG.warn("\t\tFlooding Originating Switch %d using Buffer ID"%(iDpid))
                    req = parser.OFPPacketOut(dp, buffer_id = buffer_id, in_port=in_port, actions=actions)
                    switch.dp.send_msg(req)
                    
                elif len(actions) > 0:
                    LOG.warn("\t\tFlooding Switch %d"%(iDpid))
                    req = parser.OFPPacketOut(dp, buffer_id = ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
                    switch.dp.send_msg(req)        
            
        def output(tDpid, port):
            LOG.warn("\tOutputting packet")

            action = parser.OFPActionOutput(port, 0)
            
            if buffer_id != None:
                #Drop the packet from the buffer on the incoming switch to prevent buffer overflows.
                if tDpid != dpid:
                    LOG.warn("\tDropping buffer_id on incoming switch %d"%(dpid))
                    actions = []
                #Or forward if that is also the destination switch.
                else:
                    LOG.warn("\tOutputting via buffer_id on switch %d"%(tDpid))
                    actions = [ action ]
                    
                req = parser.OFPPacketOut(dp, buffer_id = buffer_id, in_port=in_port, actions=actions)
                dp.send_msg(req)
                
            #Forward packet through data-field.
            if buffer_id == None or tDpid != dpid:
                LOG.warn("\tOutputting on outgoing switch %d"%(tDpid))
                switch = self.G.node[tDpid]['switch']
                actions = [ action ]
                req = parser.OFPPacketOut(dp, buffer_id = ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
                switch.dp.send_msg(req)
        
        msg = ev.msg
        dp = msg.datapath
        dpid = msg.datapath.id
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id

        ofp = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser        
        
        if msg.reason == ofp.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofp.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofp.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:

            reason = 'unknown'
        
        data = msg.data        
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_ = pkt.get_protocol(arp.arp)

        
        #LOG.debug("OpenFlowBackupRules: New incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))        

        if eth.dst == '33:33:00:00:00:02':
            return
        if self.CONF.observe_links and eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore LLDP related messages IF topology module has been enabled.
            # LOG.debug("\tIgnored LLDP packet due to enabled topology module")
            # LOG.debug("\t%s"%(msg))
            # LOG.debug("\t%s"%(pkt))
            return

        LOG.warn("OpenFlowBackupRules: Accepted incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))                
        LOG.debug("\t%s"%(msg))        
        LOG.debug("\t%s"%(pkt))

        SwitchPort = namedtuple('SwitchPort', 'dpid port')        
        
        #if in_port not in [port for _,port  in self.G.neighbors(dpid, data="port")]:
        if in_port not in [self.G.get_edge_data(dpid, jDpid)['port'] for jDpid in self.G.neighbors(dpid)]:
            # only relearn locations if they arrived from non-interswitch links
            self.mac_learning[eth.src] = SwitchPort(dpid, in_port)	#relearn the location of the mac-address
            #only want to look at arp messages
            if arp_ !=  None:
                #only if we have new information, do we want
                if arp_.src_ip in self.IP_learning.keys():
                    if self.IP_learning[arp_.src_ip] != [dpid, in_port]:
                        self.IP_learning[arp_.src_ip] = [dpid, in_port]
                        self.topology_update = datetime.now()
                        LOG.warn("\tUpdated IP address")
                else:
                    self.IP_learning[arp_.src_ip] = [dpid, in_port]
                    self.topology_update = datetime.now()
                    LOG.warn("\tLearned IP address")


            LOG.warn("\t%s"%(msg))

            LOG.warn("\tLearned or updated MAC address")
        else:
            LOG.warn("\tIncoming packet from switch-to-switch link, this should NOT occur.")
            #DROP it
        if mac.is_multicast( mac.haddr_to_bin(eth.dst) ):
            #Maybe we should do something with preconfigured broadcast trees, but that is a different problem for now.
            flood()
            LOG.warn("\tFlooded multicast packet")
        elif eth.dst not in self.mac_learning:
            flood()
            LOG.warn("\tFlooded unicast packet, unknown MAC address location")
        
        #ARP messages are too infrequent and volatile of nature to create flows for, output immediately
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            output(self.mac_learning[eth.dst].dpid, self.mac_learning[eth.dst].port)
            LOG.warn("\tProcessed ARP packet, send to recipient at %s"%(self.mac_learning[eth.dst],))
        #Create flow and output or forward.
        else:
            self._install_path(dpid, in_port, pkt)
             
            #Output the first packet to its destination
            output(self.mac_learning[eth.dst].dpid, self.mac_learning[eth.dst].port)
            LOG.warn("\tProcessed packet + called install_path(), sent to recipient at %s"%(self.mac_learning[eth.dst],))



        

    def _calc_ForwardingMatrix(self):
        while self.is_active: # and self.path_computation == "sr":
            #Wait for actual topology to set
            if self.topology_update == None:
                LOG.warn("_calc_ForwardingMatrix(): Wait for actual topology to set")
            #Wait for the topology to settle for 10 seconds
            elif self.topology_update + timedelta(seconds = 10) >= datetime.now():
                LOG.warn("_calc_ForwardingMatrix(): Wait for the topology to settle for 10 seconds")
            elif self.forwarding_update == None or self.topology_update > self.forwarding_update:
                LOG.warn("_calc_ForwardingMatrix(): Compute new Forwarding Matrix")
                forwarding_update_start = datetime.now()
                #Update the version of this
                self.fw = nx.all_pairs_dijkstra_path(self.G)
                self.fw2 = extended_disjoint(self.G, node_disjoint=False, edge_then_node_disjoint=False)

                #self.fw = nx.extended_disjoint(self.G, node_disjoint = self.node_disjoint, edge_then_node_disjoint = self.edge_then_node_disjoint)
                #for each switch in the forwaring matrix
                for _s in self.fw:
                    src = _s
                    dp = self.G.node[src]['switch'].dp
                    ofp = dp.ofproto
                    parser = dp.ofproto_parser
                    #for each destination for this switch
                    self.sr_switches[_s].handle_fw(self.fw[_s], self.G.node[src]['switch'])

                            # if src == 11 and dst == 76:
                            #
                            #     group_id = 11014
                            #     actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=14+15000), parser.OFPActionGroup(1114)]
                            #     buckets = [parser.OFPBucket(actions=actions)]
                            #     req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_INDIRECT, group_id=group_id, buckets=buckets)
                            #     dp.send_msg(req)
                            #
                            #
                            #     group_id = 11051
                            #     actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=51+15000), parser.OFPActionGroup(11014)]
                            #     buckets = [parser.OFPBucket(actions=actions)]
                            #     req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_INDIRECT, group_id=group_id, buckets=buckets)
                            #     dp.send_msg(req)
                            #
                            # if src == 76 and dst == 11:
                            #
                            #     group_id = 76051
                            #     actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=51+15000), parser.OFPActionGroup(7651)]
                            #     buckets = [parser.OFPBucket(actions=actions)]
                            #     req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_INDIRECT, group_id=group_id, buckets=buckets)
                            #     dp.send_msg(req)
                            #
                            #
                            #     group_id = 76014
                            #     actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=14+15000), parser.OFPActionGroup(76051)]
                            #     buckets = [parser.OFPBucket(actions=actions)]
                            #     req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_INDIRECT, group_id=group_id, buckets=buckets)
                            #     dp.send_msg(req)


                    for ip_dst, swp in self.IP_learning.items():
                        dst = swp[0]
                        port = swp[1]

                        match = parser.OFPMatch(eth_type=0x800,ipv4_dst=ip_dst)
                        _match = parser.OFPMatch(**dict(match.items()))
                        group_id = src*100 + dst

                        # if src == 11 and dst == 76:
                        #     group_id = 11051
                        # if src == 76 and dst == 11:
                        #     group_id = 76014

                        if dst == src:
                            actions = [parser.OFPActionOutput(port)]
                        else:
                            actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=dst+15000), parser.OFPActionGroup(group_id)]
                        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst, priority=1000)
                        LOG.debug(req)
                        dp.send_msg(req)

                        if dst != src:
                            match = parser.OFPMatch(eth_type=0x8847, mpls_label = dst+15000)
                            _match = parser.OFPMatch(**dict(match.items()))
                            actions = [parser.OFPActionGroup(group_id)]
                            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst, priority=1000)
                            LOG.debug(req)
                            dp.send_msg(req)


                        # LOG.warn("\t\tConfigure switch %d to forward to group %d "%(dpid, group_id))
                        #
                        # _match = parser.OFPMatch(in_port=in_port, **dict(match.items()))
                        # actions = [parser.OFPActionGroup(group_id)]
                        # inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        # req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst)
                        # LOG.debug(req)
                        # dp.send_msg(req)

                self.forwarding_update = datetime.now()
                LOG.warn("_calc_ForwardingMatrix(): Took %s"%(self.forwarding_update - forwarding_update_start))
                
            hub.sleep(1)
        
        
    def _install_path(self, dpid, in_port, pkt):
        switch = self.G.node[dpid]['switch']
        dp = switch.dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser            
        
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = self.mac_learning[eth.dst]

        if self.path_computation == "shortest_path":
            LOG.warn("\tLook up path from switch %d to %s"%(dpid, dst))
            #path = self._get_path(dpid, dst.dpid)
            path = nx.shortest_path(self.G, source=dpid, target=dst.dpid, weight='weight')
            if path == None:
                LOG.error("\t\tNo path found")
                return -1

            LOG.warn("\t\tPath found")

            match = parser.OFPMatch(eth_dst=eth.dst)


            dpid = path[0]
            #for (nexthop, port) in path:
            for i in range(1, len(path)):
                nexthop = path[i]
                port = self.G.edge[dpid][nexthop]['port']
                LOG.warn("\t\tConfigure switch %d to forward to switch %d over port %d"%(dpid, nexthop,port))

                actions = [parser.OFPActionOutput(port)]
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                req = parser.OFPFlowMod(datapath=dp, match=match, instructions = inst)
                dp.send_msg(req)

                dpid = nexthop
                dp = self.G.node[dpid]['switch'].dp
                ofp = dp.ofproto
                parser = dp.ofproto_parser

            assert dpid == dst.dpid
            port = dst.port
            LOG.warn("\t\tConfigure switch %d to output on port %d"%(dpid,port))

            actions = [parser.OFPActionOutput(port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=match, instructions = inst)
            dp.send_msg(req)
            
        elif self.path_computation == "simple_disjoint" or self.path_computation == "bhandari":
            LOG.warn("\tLook up disjoint paths from switch %d to %s using %s algorithm"%(dpid, dst, self.path_computation))
            try:
                if self.path_computation == "bhandari":
                    dists,paths = nx.bhandari(self.G, source=dpid, target=dst.dpid, weight='weight', node_disjoint = self.node_disjoint, k=self.number_of_disjoint_paths)
                elif self.path_computation == "simple_disjoint":
                    dists,paths = nx.simple_disjoint(self.G, source=dpid, target=dst.dpid, weight='weight', node_disjoint = self.node_disjoint, k=self.number_of_disjoint_paths)
                else:
                    raise NotImplementedError("To-Be-Done: Disjoint path computation method %s not implemented."%(self.path_computation))
            except nx.NetworkXNoPath as e:
                LOG.error("\t\t%s"%(e))
                return -1
            
            match = parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst)

            group_id = dpid*2**16 + dst.dpid #variabilize group ids
            
            LOG.warn("\t\tTell switch %d to create fast failover group 0x%x with buckets:"%(dpid, group_id))

            #Fill in buckets
            output_switch_ports = [(path[1],self.G.edge[dpid][path[1]]['port']) for path in paths]
            buckets = [parser.OFPBucket(watch_port=port, actions=[parser.OFPActionOutput(port)]) for (switch, port) in output_switch_ports]
            for switch, port in output_switch_ports:
                LOG.warn("\t\t\tswitch %d over port %d"%(switch, port))
            
            req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)
            LOG.debug(req)
            dp.send_msg(req)

            LOG.warn("\t\tConfigure switch %d to forward to group %d "%(dpid, group_id))
            
            _match = parser.OFPMatch(in_port=in_port, **dict(match.items()))
            actions = [parser.OFPActionGroup(group_id)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst)
            LOG.debug(req)
            dp.send_msg(req)

            in_switch, in_port = output_switch_ports[0]
            switch, port = output_switch_ports[1]
            LOG.warn("\t\tConfigure crankback rule on switch %d from switch %d, port %d to switch %d, port %d"%(dpid, in_switch, in_port, switch, port))

            _match = parser.OFPMatch(in_port=in_port, **dict(match.items()))
            actions = [parser.OFPActionOutput(port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst)
            LOG.debug(req)
            dp.send_msg(req)
            
                        
            #Fill in rest of path:            
            for path in paths:
                prevhop = path[0]
                dpid = path[1]
                dp = self.G.node[dpid]['switch'].dp
                ofp = dp.ofproto
                parser = dp.ofproto_parser
                
                for i in range(2, len(path)):
                    nexthop = path[i]
                    port = self.G.edge[dpid][nexthop]['port']
                    in_port = self.G.edge[dpid][prevhop]['port']
                    
                    if path is not paths[-1]:
                        LOG.warn("\t\tConfigure switch %d to forward to switch %d over port %d, or crankback otherwise."%(dpid, nexthop,port))
                        
                        buckets = []
                        buckets.append(parser.OFPBucket(watch_port=port, actions=[parser.OFPActionOutput(port)]))
                        buckets.append(parser.OFPBucket(watch_port=in_port, actions=[parser.OFPActionOutput(ofp.OFPP_IN_PORT)]))
                        
                        req = parser.OFPGroupMod(datapath=dp, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)
                        LOG.debug(req)
                        dp.send_msg(req)
                        
                        _match = parser.OFPMatch(in_port=in_port, **dict(match.items()))
                        actions = [parser.OFPActionGroup(group_id)]
                        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst)
                        LOG.debug(req)
                        dp.send_msg(req)
                        
                        _match = parser.OFPMatch(in_port=port, **dict(match.items()))
                        actions = [parser.OFPActionOutput(in_port)]
                        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst)
                        LOG.debug(req)
                        dp.send_msg(req)
                        
                    else:
                        LOG.warn("\t\tConfigure switch %d to forward to switch %d over port %d."%(dpid, nexthop,port))
                        
                        _match = parser.OFPMatch(in_port=in_port, **dict(match.items()))
                        actions = [parser.OFPActionOutput(port)]
                        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst)
                        LOG.debug(req)
                        dp.send_msg(req)
                    
                    prevhop = dpid
                    dpid = nexthop
                    dp = self.G.node[dpid]['switch'].dp
                    ofp = dp.ofproto
                    parser = dp.ofproto_parser    
            
            #Final forrward at destination        
            port = dst.port
            LOG.warn("\t\tConfigure switch %d to output on port %d"%(dpid,port))
            
            actions = [parser.OFPActionOutput(port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=match, instructions = inst)
            dp.send_msg(req)
            
        elif self.path_computation == "extended_disjoint":
            LOG.warn("\tLook up disjoint paths from switch %d to %s using %s algorithm"%(dpid, dst, self.path_computation))
            
            match = parser.OFPMatch(eth_dst=eth.dst)
            dst = self.mac_learning[eth.dst]
            group_id = dst.dpid
            
            LOG.warn("\t\tConfigure switch %d to add VLAN-ID and forward to group %d", dpid, dst.dpid)
            _match = parser.OFPMatch(vlan_vid=(ofp.OFPVID_NONE), in_port=in_port, **dict(match.items()))
            actions = [parser.OFPActionPushVlan(), parser.OFPActionGroup(group_id)]            
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst)
            dp.send_msg(req)            
            
            dpid = dst.dpid
            switch = self.G.node[dpid]['switch']
            dp = switch.dp
            ofp = dp.ofproto
            parser = dp.ofproto_parser   
            
            #Final forrward at destination        
            
            port = dst.port
            LOG.warn("\t\tConfigure switch %d to remove VLAN-ID and output on port %d"%(dpid,port))
            _match = parser.OFPMatch(vlan_vid=(ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT), **dict(match.items()))
            
            actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions = inst)
            dp.send_msg(req)
                                        
        else:
            print()
            #raise NotImplementedError("To-Be-Done: Path computation method %s not implemented."%(self.path_computation))
            

        
        LOG.warn("\t\tDone.")
        return -2
    
        def close(self):
            self.is_active = False
        
app_manager.require_app('ryu.topology.switches', api_style=False)
