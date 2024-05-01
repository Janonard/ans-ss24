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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
import datetime

port_to_router_mac = {
    1: "00:00:00:00:01:01",
    2: "00:00:00:00:01:02",
    3: "00:00:00:00:01:03",
}

port_to_router_ip = {
    1: "10.0.1.1",
    2: "10.0.2.1",
    3: "192.168.1.1",
}

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, priority=0)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, match, actions, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match, instructions=inst, **kwargs)
        datapath.send_msg(mod)

    def send_new_message(self, dp, out_port, data):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        dp.send_msg(
            ofp_parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
                actions=[ofp_parser.OFPActionOutput(out_port)],
                data=data
            )
        )

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        dp: Datapath = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
        print(datetime.datetime.now(), eth_pkt.src, eth_pkt.dst)

        eth_src = eth_pkt.src
        # Timeout is a little bit short, but easier to see that it works
        self.add_flow(dp, ofp_parser.OFPMatch(eth_dst=eth_src), [ofp_parser.OFPActionOutput(in_port)], idle_timeout=15, hard_timeout=15)

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
            actions=actions, data=data)
        dp.send_msg(out)

        arp_pkt: arp.arp = pkt.get_protocol(arp.arp)
        if arp_pkt is not None and arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.dst_ip == port_to_router_ip[in_port]:
                response_pkt = packet.Packet()
                response_pkt.add_protocol(
                    ethernet.ethernet(src=port_to_router_mac[in_port], dst=eth_pkt.src, ethertype=eth_pkt.ethertype)
                )
                response_pkt.add_protocol(
                    arp.arp(opcode=arp.ARP_REPLY,
                            src_mac=port_to_router_mac[in_port], src_ip=port_to_router_ip[in_port],
                            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
                )
                self.send_new_message(dp, in_port, response_pkt)
                