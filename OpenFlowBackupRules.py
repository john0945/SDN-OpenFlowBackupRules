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

from collections import namedtuple, defaultdict

from ryu.controller.handler import CONFIG_DISPATCHER

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

from ryu.lib import mac, hub

import networkx as nx
import calculate_backup as cb
import label_stack
from datetime import datetime, timedelta

import pprint
pp = pprint.PrettyPrinter()
LOG = logging.getLogger(__name__)

class OpenFlowBackupRules(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches,
    }
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OpenFlowBackupRules, self).__init__(*args, **kwargs)

        self.sr_switches = {}
        self.edge_switches = []
        self.G = nx.DiGraph()
        self.mac_learning = {}
        self.IP_learning = {}

        #parameters
        self.path_computation = "sr"#"shortest_path"
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

# I'll need to configure this to trigger a topology update
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

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            LOG.warn("ARP ARP ARP ARP ARP")
        else:
            LOG.warn("OpenFlowBackupRules: Accepted incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))
        # LOG.debug("\t%s"%(msg))
        # LOG.debug("\t%s"%(pkt))

        SwitchPort = namedtuple('SwitchPort', 'dpid port')        
        
        #if in_port not in [port for _,port  in self.G.neighbors(dpid, data="port")]:
        if in_port not in [self.G.get_edge_data(dpid, jDpid)['port'] for jDpid in self.G.neighbors(dpid)]:
            # only relearn locations if they arrived from non-interswitch links
            self.mac_learning[eth.src] = SwitchPort(dpid, in_port)	#relearn the location of the mac-address
            #only want to look at arp messages
            if arp_ !=  None:
                #only if we have new information, do we want
                ip = arp_.src_ip
                if ip in self.IP_learning.keys():
                    if self.IP_learning[ip] != [dpid, in_port]:
                        self.IP_learning[ip] = [dpid, in_port]
                        LOG.warn("\tUpdated IP address")
                        LOG.warn("\tTO DO: delete old flow rules and install new ones")
                else:
                    self.IP_learning[ip] = [dpid, in_port]
                    LOG.warn("\tLearned IP address")
                    #add to list of edge switches if it isn't already there
                    new = False
                    if dpid not in self.edge_switches:
                        self.edge_switches.append(dpid)
                        new = True

                    self._install_edge_rules(dpid, in_port, ip, new)


            # LOG.warn("\t%s"%(msg))

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
            #Output the first packet to its destination
            output(self.mac_learning[eth.dst].dpid, self.mac_learning[eth.dst].port)

    def _calc_ForwardingMatrix(self):
        while self.is_active: # and self.path_computation == "sr":
            #Wait for actual topology to set
            if self.topology_update == None:
                LOG.warn("_calc_ForwardingMatrix(): Wait for actual topology to set")
            #Wait for the topology to settle for 10 seconds
            elif self.topology_update + timedelta(seconds = 5) >= datetime.now():
                LOG.warn("_calc_ForwardingMatrix(): Wait for the topology to settle for 5 seconds")
            elif self.forwarding_update == None or self.topology_update > self.forwarding_update:
                LOG.warn("_calc_ForwardingMatrix(): Compute new Forwarding Matrix")
                forwarding_update_start = datetime.now()

                #Update the version of this
                self.fw, self.link_fw, self.succ = cb.calculate_backup(self.G)

                #for each switch in the forwarding matrix
                for _s in self.fw:
                    labels = {}
                    next_hop = {}
                    for k,v in self.link_fw[_s].items():
                        next_hop[k] = v[1]
                        labels[k] = label_stack.get(self.fw, v)

                    #for each destination for this switch
                    paths = self.fw[_s]
                    switch = self.G.node[_s]['switch']
                    self.sr_switches[_s].handle_fw(paths, labels, next_hop, switch)



                # for failure in self.link_fw.keys():
                #     source = failure[0]
                #     neighbour = failure[1]
                #     paths = self.link_fw[failure]
                #     for dest, path in paths.items():
                #         self.sr_switches[source].handle_link_fw(lb, dest, path[1], self.G.node[source]['switch'])

                self.forwarding_update = datetime.now()
                LOG.warn("_calc_ForwardingMatrix(): Took %s"%(self.forwarding_update - forwarding_update_start))
                
            hub.sleep(1)

    def _install_edge_rules(self, dpid, in_port, ip, new):

        #if this is a new edge, add the existing locations
        if new:
            switch = self.G.node[dpid]['switch']
            dp = switch.dp
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            for ip_dst, swp in self.IP_learning.items():
                dst = swp[0]
                port = swp[1]
                group_id = dpid * 100 + dst
                if dpid != dst:
                    host_label = int(ip_dst.split('.')[-1]) + 16000
                    match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst)
                    _match = parser.OFPMatch(**dict(match.items()))
                    actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=host_label), parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=dst + 15000),
                               parser.OFPActionGroup(group_id)]

                    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                    req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst, priority=1000)
                    LOG.debug(req)
                    dp.send_msg(req)

        for edge in self.edge_switches:
            switch = self.G.node[edge]['switch']
            dp = switch.dp
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            host_label = int(ip.split('.')[-1]) + 16000

            group_id = edge * 100 + dpid # here, dpid is the destination
            if dpid == edge:
                match = parser.OFPMatch(eth_type=0x8847, mpls_label=host_label)
                _match = parser.OFPMatch(**dict(match.items()))
                actions = [parser.OFPActionPopMpls(ethertype=0x800), parser.OFPActionOutput(in_port)]
            else:
                match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip)
                _match = parser.OFPMatch(**dict(match.items()))
                actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=host_label), parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=dpid + 15000),
                           parser.OFPActionGroup(group_id)]

            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, match=_match, instructions=inst, priority=1000)
            LOG.debug(req)
            dp.send_msg(req)


        LOG.warn("\t\tDone.")
        return -2
    
        def close(self):
            self.is_active = False
        
app_manager.require_app('ryu.topology.switches', api_style=False)
