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


    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev: event.EventSwitchEnter):
        self.topo = nx.DiGraph()
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


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TODO: handle new packets at the controller
        empty_ports = set(range(1, 5)).difference({out_port for (_, _, out_port) in self.topo.out_edges(dpid, data="out_port")})

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
        
        if in_port in empty_ports:
            src_address = eth_pkt.src.replace(":", "")
            self.topo.add_node(src_address)
            self.topo.add_edge(src_address, datapath.id)
            self.topo.add_edge(datapath.id, src_address, out_port=in_port)
            nx.nx_pydot.write_dot(self.topo, "topo.dot")
