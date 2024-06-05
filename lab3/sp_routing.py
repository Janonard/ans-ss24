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

from concurrent.futures import ThreadPoolExecutor
import time
import datetime
import sys
import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import *

from ryu.topology import event
from ryu.topology.api import get_link

from ipaddress import IPv4Address
import topo


class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.topo_net = topo.Fattree(4)

        def request_port_stats():
            try:
                while True:
                    # Await next interval
                    time.sleep(5)

                    # Write current data
                    with open("packet_counts.json", "w") as out_file:
                        json.dump(self.packet_data, out_file)

                    for switch in self.topo_net.switches:
                        dp: Datapath = switch.datapath
                        if dp is None:
                            continue

                        ofproto = dp.ofproto
                        parser = dp.ofproto_parser

                        # Send a request for stats
                        dp.send_msg(parser.OFPPortStatsRequest(
                            dp, 0, ofproto.OFPP_ANY))
            except Exception as e:
                print(e, file=sys.stderr)

        self.thread_pool = ThreadPoolExecutor()
        self.thread_pool.submit(request_port_stats)
        self.packet_data = list()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def handle_ports_stats_reply(self, ev):
        dp: Datapath = ev.msg.datapath
        ip = IPv4Address(dp.id)
        data = dict()
        for stat in ev.msg.body:
            data[stat.port_no] = stat.tx_packets
        self.packet_data.append({"ip": str(ip), "time": str(
            datetime.datetime.now()), "counts": data})

    # Topology discovery

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        dp = ev.switch.dp
        switch_ip = IPv4Address(dp.id)
        switch = self.topo_net.node_by_ip(switch_ip)
        switch.datapath = dp

        for link in get_link(self, dp.id):
            src_ip = IPv4Address(link.src.dpid)
            dst_ip = IPv4Address(link.dst.dpid)

            other_ip = src_ip if dst_ip == switch_ip else dst_ip
            edge = next(filter(lambda e: other_ip in [
                        e.lnode.ip, e.rnode.ip], switch.edges))

            if src_ip == edge.lnode.ip:
                edge.lport = link.src.port_no
                edge.rport = link.dst.port_no
            else:
                edge.lport = link.dst.port_no
                edge.rport = link.src.port_no

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
        dst_node = self.topo_net.node_by_ip(dst_ip)

        print(f"Packet in: {src_ip} -> {dst_ip}; Switch {switch_ip}")

        # Computing the shortest path
        path = self.topo_net.single_source_shortest_paths(
            switch_node, dst_node)[dst_node]

        # Forwarding the packet via the last switch on the path.
        # We may not know the out-port to the host if it has not sent a packet yet.
        # We therefore try to find out which ports the host won't be connected to.
        # If we find that we know the out-port, we will send out the packet directly.
        # Otherwise we send the packet to all ports where the host might be attached.
        last_switch = path[-2]

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

        # Installing forwarding rules according to the shortest path
        # We exclude the final edge switch, since it learns its forwarding rule via port learning.
        for i_node in range(len(path)-2):
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

        # Install host forwarding rule
        self.add_flow(
            switch_node.datapath,
            1,
            parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP, ipv4_dst=str(src_ip)),
            [parser.OFPActionOutput(msg.match["in_port"])]
        )
        self.add_flow(
            switch_node.datapath,
            1,
            parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_ARP, arp_tpa=str(src_ip)),
            [parser.OFPActionOutput(msg.match["in_port"])]
        )
