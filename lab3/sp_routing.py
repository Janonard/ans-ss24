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
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import *

from ryu.topology import event, switches
from ryu.topology.switches import Switch, Link, Port
from ryu.topology.api import get_switch, get_link
from ryu.controller.controller import Datapath
from ryu.app.wsgi import ControllerBase

import networkx as nx

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        self.topo = nx.DiGraph()
        self.hosts = list()

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev: event.EventSwitchEnter):
        self.topo = nx.DiGraph()
        for switch in get_switch(self, None):
            self.topo.add_node(switch.dp.id, dp=switch.dp)

        for link in get_link(self, None):
            self.topo.add_edge(link.src.dpid, link.dst.dpid, out_port=link.src.port_no)
            self.topo.add_edge(link.dst.dpid, link.src.dpid, out_port=link.dst.port_no)

        nx.nx_pydot.write_dot(self.topo, "topo.dot")


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

    def get_occupied_ports(self, node):
        return [out_port for (_, _, out_port) in self.topo.out_edges(node, data="out_port")]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
        src_name = eth_pkt.src.replace(":", "")
        dst_name = eth_pkt.dst.replace(":", "")

        occupied_ports = [out_port for (_, _, out_port) in self.topo.out_edges(dpid, data="out_port")]
        if in_port not in occupied_ports:
            # The packet comes from a host that we don't know yet. Add it to the topology.
            self.topo.add_edge(src_name, datapath.id)
            self.topo.add_edge(datapath.id, src_name, out_port=in_port)
            self.hosts.append(src_name)
            nx.nx_pydot.write_dot(self.topo, "topo.dot")

        if eth_pkt.dst == "ff:ff:ff:ff:ff:ff":
            # Broadcast the packet manually to all hosts
            for host in self.hosts:
                if host == src_name:
                    continue

                dpid, _, out_port = list(self.topo.in_edges(host, data="out_port"))[0]
                dp = self.topo.nodes[dpid]["dp"]

                dp.send_msg(
                    parser.OFPPacketOut(
                        datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                        actions=[parser.OFPActionOutput(out_port)],
                        data=msg.data
                    )
                )

        else:
            # Ignore unkown targets
            if dst_name not in self.topo.nodes:
                return
            
            # Get the shortest path and set up flow rules for switches along the path
            path = nx.shortest_paths.shortest_path(self.topo, dpid, dst_name)
            for i in range(0, len(path)-1):
                out_dp = self.topo.nodes[path[i]]["dp"]
                out_port = self.topo[path[i]][path[i+1]]["out_port"]
                self.add_flow(
                    out_dp,
                    1,
                    parser.OFPMatch(eth_src=eth_pkt.src, eth_dst=eth_pkt.dst),
                    [parser.OFPActionOutput(out_port)]
                )
            
            # Logging
            if src_name in self.hosts and dst_name in self.hosts:
                print(f"{src_name} -> {path[:-1]} -> {dst_name}")
            
            # Forward the packet via the last switch on the shortest path
            # (No need to send it via the whole path)
            dp = self.topo.nodes[path[-2]]["dp"]
            out_port = self.topo[path[-2]][path[-1]]["out_port"]
            dp.send_msg(
                parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                    actions=[parser.OFPActionOutput(out_port)],
                    data=msg.data
                )
            )
