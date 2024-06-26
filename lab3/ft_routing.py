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
from ryu.lib.packet import *

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

from ipaddress import IPv4Address
from ipaddress import IPv4Network
import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.k = 4
        self.topo_net = topo.Fattree(self.k)

    # Extracts the value of the octet from the IP
    def get_octet_value(self, ip_address, octet_number):
        return int(str(ip_address).split('.')[octet_number])
   
    def get_network_address(self, ip_address, subnet):
        return IPv4Network(f"{ip_address}/{subnet}", strict = False).network_address

    # Topology discovery

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Add IP information to topo switch
        dp = ev.switch.dp
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
            port = link.dst.port_no if dst_ip == switch_ip else link.src.port_no
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

            if self.get_octet_value(switch_ip, 1) == self.get_octet_value(other_ip, 1):
                # aggregation -> edge
                if self.get_octet_value(switch_ip, 2) > self.get_octet_value(other_ip, 2):
                    print("create rule:", switch_ip, self.get_network_address(other_ip, 24), port)
                    self.add_flow(
                        dp,
                        2,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP,
                                        ipv4_dst=(self.get_network_address(other_ip, 24), "255.255.255.0")),
                        [parser.OFPActionOutput(port)]
                    )
                    self.add_flow(
                        dp,
                        2,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP,
                                        arp_tpa=(self.get_network_address(other_ip, 24), "255.255.255.0")),
                        [parser.OFPActionOutput(port)]
                    )
            else:
                # core -> aggregation
                if self.get_octet_value(switch_ip, 1) > self.get_octet_value(other_ip, 1):
                    print("create rule:", switch_ip, self.get_network_address(other_ip, 16), port)
                    self.add_flow(
                        dp,
                        2,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP,
                                        ipv4_dst=self.get_network_address(other_ip, 16)),
                        [parser.OFPActionOutput(port)]
                    )
                    self.add_flow(
                        dp,
                        2,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP,
                                        arp_tpa=self.get_network_address(other_ip, 16)),
                        [parser.OFPActionOutput(port)]
                    )
                # aggregation -> Core
                else:
                    # Any core switch is fine for now...
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP,
                                        ipv4_src=("10.0.0.0", "255.0.0.0")),
                        [parser.OFPActionOutput(port)]
                    )
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP,
                                        arp_spa=("10.0.0.0", "255.0.0.0")),
                        [parser.OFPActionOutput(port)]
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
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    # Packet from unknown host reaches the edge switch
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        switch_ip = IPv4Address(dpid)
        switch_node = self.topo_net.node_by_ip(switch_ip)
        switch_port = msg.match["in_port"]

        # Packet header parsing
        pkt = packet.Packet(msg.data)
        arp_pkt: arp.arp = pkt.get_protocol(arp.arp)
        ipv4_pkt: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt is not None:
            src_ip = IPv4Address(arp_pkt.src_ip)
            dst_ip = IPv4Address(arp_pkt.dst_ip)
        elif ipv4_pkt is not None:
            src_ip = IPv4Address(ipv4_pkt.src)
            dst_ip = IPv4Address(ipv4_pkt.dst)
        else:
            return  # Neither IP nor ARP, ignore packet
        
        # Logging
        print(f"{src_ip} -> {dst_ip} (Switch {switch_ip})")
        
        # Edge switch, handling an outgoing packet
        if self.get_octet_value(switch_ip, 2) == self.get_octet_value(src_ip, 2) and self.get_octet_value(switch_ip, 1) == self.get_octet_value(src_ip, 1):
            
            # Port learning for hosts
            for edge in switch_node.edges:
                if edge.lnode == switch_node and edge.rnode.ip == src_ip:
                    edge.lport = switch_port
                elif edge.rnode == switch_node and edge.lnode.ip == src_ip:
                    edge.rport = switch_port
            
            # edge -> server flow rules
            self.add_flow(
                datapath,
                2,
                parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP, ipv4_dst=src_ip),
                [parser.OFPActionOutput(switch_port)]
            )
            self.add_flow(
                datapath,
                2,
                parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP, arp_tpa=src_ip),
                [parser.OFPActionOutput(switch_port)]
            )

            # edge -> aggregation flow rules
            # Find any aggregation switch to forward to
            out_port = None
            for edge in switch_node.edges:
                if edge.lnode == switch_node and self.get_octet_value(edge.rnode.ip, 3) == 1:
                    out_port = edge.lport
                    break
                elif edge.rnode == switch_node and self.get_octet_value(edge.lnode.ip, 3) == 1:
                    out_port = edge.rport
                    break
            assert out_port is not None, f"Switch: {switch_ip}"

            self.add_flow(
                datapath,
                1,
                parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP,
                                ipv4_src=src_ip),
                [parser.OFPActionOutput(out_port)]
            )
            self.add_flow(
                datapath,
                1,
                parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP,
                                arp_tpa=src_ip),
                [parser.OFPActionOutput(out_port)]
            )
        
        # Forward packet via final edge switch
        final_switch_ip = str(dst_ip).split(".")
        final_switch_ip[3] = "1"
        final_switch_ip = IPv4Address(".".join(final_switch_ip))
        final_switch = self.topo_net.node_by_ip(final_switch_ip)

        out_ports = list(range(1, 5))
        for edge in final_switch.edges:
            if edge.lnode == final_switch:
                edge_out_port = edge.lport
                edge_dst = edge.rnode
            else:
                edge_out_port = edge.rport
                edge_dst = edge.lnode

            if edge_out_port is None:
                continue

            if edge_dst.ip == dst_ip:
                # We know exactly where to send the packet to, short circuit
                out_ports = [edge_out_port]
                break
            else:
                # We know that this port goes to a switch/host we don't want to address.
                # Remove this port
                out_ports.remove(edge_out_port)

        final_switch.datapath.send_msg(
            parser.OFPPacketOut(
                datapath=final_switch.datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(out_port) for out_port in out_ports],
                data=msg.data
            )
        )





        