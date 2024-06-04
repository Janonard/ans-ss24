"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

from ipaddress import IPv4Address
import topo

class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.topo_net = topo.Fattree(4)

    # Extracts the value of the octet from the IP
    def get_octet_value(self, ip_address, octet_number):
        return int(str(ip_address).split('.')[octet_number - 1])
   
    def get_network_address(self, ip_address, subnet):
        return ipaddress.ip_interface(f"{ip_address}/{subnet}")

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Add IP information to topo switch
        dp = ev.dp
        switch_ip = IPv4Address(dp.id)
        switch = self.topo_net.node_by_ip(switch_ip)
        switch.datapath = dp
        parser = dp.ofproto_parser

        
        # Get all links from new switch
        for link in get_link(self, dp.id):
            src_ip = IPv4Address(link.src.dpid)
            dst_ip = IPv4Address(link.dst.dpid)
 
            # Match link to topo edge
            other_ip = src_ip if dst_ip == switch_ip else dst_ip
            own_port = link.dst.port_no if dst_ip == switch_ip else link.src.port_no
            other_port = link.src.port_no if dst_ip == switch_ip else link.dst.port_no
            other_dp = self.topo_net.node_by_ip(other_ip).datapath
            edge = next(filter(lambda e: other_ip in [
                        e.lnode.ip, e.rnode.ip], switch.edges))
 
            # Add port information to topo edge
            if src_ip == edge.lnode.ip:
                edge.lport = link.src.port_no
                edge.rport = link.dst.port_no
            else:
                edge.lport = link.dst.port_no
                edge.rport = link.src.port_no
 
            # Add flow rules for connected device
            
            # Server - Edge
            if self.get_octet_value(other_ip, 3) != 1:
                self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst=other_ip),
                        [parser.OFPActionOutput(own_port)]
                    )
            # Edge - Aggregation
            elif self.get_octet_value(switch_ip, 1) == self.get_octet_value(other_ip, 1):
 
                # own switch = aggregation
                if self.get_octet_value(switch_ip, 2) > self.get_octet_value(other_ip, 2):
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(other_ip, 24)),
                        [parser.OFPActionOutput(own_port)]
                    )
                    self.add_flow(
                        other_dp,
                        1,
                        parser.OFPMatch(ipv4_dst="0.0.0.0/0"),
                        [parser.OFPActionOutput(other_port)]
                    )
                    
                # own switch = edge
                else:
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst="0.0.0.0/0"),
                        [parser.OFPActionOutput(own_port)]
                    )
                    self.add_flow(
                        other_dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(switch_ip, 24)),
                        [parser.OFPActionOutput(other_port)]
                    )
 
            # Aggregation - Core
            else:
 
                # own switch = core
                if self.get_octet_value(switch_ip, 1) > self.get_octet_value(other_ip, 1):
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(other_ip, 16)),
                        [parser.OFPActionOutput(own_port)]
                    )
                    self.add_flow(
                        other_dp,
                        1,
                        parser.OFPMatch(ipv4_dst="0.0.0.0/0"),
                        [parser.OFPActionOutput(other_port)]
                    )
                # own switch = aggregation
                else:
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst="0.0.0.0/0"),
                        [parser.OFPActionOutput(own_port)]
                    )
                    self.add_flow(
                        other_dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(switch_ip, 16)),
                        [parser.OFPActionOutput(other_port)]
                    )
 
        # Export topo
        with open("topo.dot", "w") as topo_file:
            topo_file.write(self.topo_net.to_dot())


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        