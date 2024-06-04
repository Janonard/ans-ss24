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
            # TODO: adjust priorities
            # TODO: round robin

            # Aggregation - Edge
            if self.get_octet_value(switch_ip, 1) == self.get_octet_value(other_ip, 1):
 
                # own switch = aggregation
                if self.get_octet_value(switch_ip, 2) > self.get_octet_value(other_ip, 2):
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(other_ip, 24)),
                        [parser.OFPActionOutput(port)]
                    )
 
            # Aggregation - Core
            else:
 
                # own switch = core
                if self.get_octet_value(switch_ip, 1) > self.get_octet_value(other_ip, 1):
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst=self.get_network_address(other_ip, 16)),
                        [parser.OFPActionOutput(port)]
                    )

                # own switch = aggregation
                else:
                    self.add_flow(
                        dp,
                        1,
                        parser.OFPMatch(ipv4_dst="0.0.0.0/0"),
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

        switch_ip = IPv4Address(dpid)
        switch_node = self.topo_net.node_by_ip(switch_ip)

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

        src_node = self.topo_net.node_by_ip(src_ip)

        octets = src_ip.split('.')
        octets[-1] = "1"
        new_ip_address = '.'.join(octets)

        edge_node = self.topo_net.node_by_ip(new_ip_address)
        dst_node = self.topo_net.node_by_ip(dst_ip)



        # Forwarding the packet via the last switch on the path.
        # We may not know the out-port to the host if it has not sent a packet yet.
        # We therefore try to find out which ports the host won't be connected to.
        # If we find that we know the out-port, we will send out the packet directly.
        # Otherwise we send the packet to all ports where the host might be attached.
        last_switch = edge_node

        out_ports = list(range(1, 5))
        for edge in last_switch.edges:
            if edge.lnode == last_switch:
                edge_out_port = edge.lport
                edge_dst = edge.rnode
            else:
                edge_out_port = edge.rport
                edge_dst = edge.lnode

            if edge_out_port is None:
                continue

            if edge_dst == dst_node:
                # We know exactly where to send the packet to, short circuit
                out_ports = [edge_out_port]
                break
            else:
                # We know that this port goes to a switch/host we don't want to address.
                # Remove this port
                out_ports.remove(edge_out_port)

        last_switch.datapath.send_msg(
            parser.OFPPacketOut(
                datapath=last_switch.datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(out_port)
                         for out_port in out_ports],
                data=msg.data
            )
        )

        # Installing forwarding rule on the edge switch
        for i_node in range(len(path)-1):
            hop_src_node = path[i_node]
            hop_dst_node = path[i_node+1]

            hop_port = None

            for edge in hop_src_node.edges:
                if edge.lnode == hop_src_node:
                    edge_dst_node = edge.rnode
                    out_port = edge.lport
                else:
                    edge_dst_node = edge.lnode
                    out_port = edge.rport

                if edge_dst_node == hop_dst_node:
                    hop_port = out_port
                    break

            if hop_port is not None:
                # In case we don't know the out port yet, we don't install a rule
                self.add_flow(
                    hop_src_node.datapath,
                    1,
                    parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP, ipv4_src=str(
                        src_ip), ipv4_dst=str(dst_ip)),
                    [parser.OFPActionOutput(hop_port)]
                )
                self.add_flow(
                    hop_src_node.datapath,
                    1,
                    parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP, arp_spa=str(
                        src_ip), arp_tpa=str(dst_ip)),
                    [parser.OFPActionOutput(hop_port)]
                )

        # Port learning for hosts
        for edge in switch_node.edges:
            if edge.lnode == switch_node and edge.rnode.ip == src_ip:
                edge.lport = msg.match["in_port"]
            elif edge.rnode == switch_node and edge.lnode.ip == src_ip:
                edge.rport = msg.match["in_port"]


        