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
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import *
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime, timedelta

ROUTER_MAC = {
    1: "00:00:00:00:01:01",
    2: "00:00:00:00:01:02",
    3: "00:00:00:00:01:03",
}

ROUTER_IP = {
    1: IPv4Address("10.0.1.1"),
    2: IPv4Address("10.0.2.1"),
    3: IPv4Address("192.168.1.1"),
}

SUBNETS = {
    1: IPv4Network("10.0.1.0/24"),
    2: IPv4Network("10.0.2.0/24"),
    3: IPv4Network("192.168.1.0/24"),
}

INTRANET = IPv4Network("10.0.0.0/16")

KNOWLEDGE_TTL = 10 # Short TTL for demonstration, usually we would pick 300-600

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        self.mac_addresses = dict()
        self.ports_to_mac_addresses = dict()

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
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match, instructions=inst, **kwargs)
        datapath.send_msg(mod)

    # Delete flow entry from the flow-table
    def del_flow(self, datapath, match, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match, command=ofproto.OFPFC_DELETE, **kwargs)
        datapath.send_msg(mod)

    # Send datapacket from specified port
    def send_packet(self, dp, out_port, data):
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
        ofp_parser: ofproto_v1_3_parser = dp.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)

        # Packet is from a switch   
        if dp.id in [1, 2]:
            print(dp.id, datetime.now(), "ETH", eth_pkt.src, eth_pkt.dst)

            self.ports_to_mac_addresses[eth_pkt.src] = (
                in_port, datetime.now() + timedelta(seconds=KNOWLEDGE_TTL))

            # Broadcast
            if eth_pkt.dst == BROADCAST_MAC:
                self.send_packet(dp, ofp.OFPP_FLOOD, pkt)
                self.add_flow(
                    dp,
                    ofp_parser.OFPMatch(eth_dst=BROADCAST_MAC),
                    [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                    priority=1
                )
                return

            # Port known
            if eth_pkt.dst in self.ports_to_mac_addresses:
                out_port, deadline = self.ports_to_mac_addresses[eth_pkt.dst]
                if deadline >= datetime.now():
                    self.add_flow(dp, ofp_parser.OFPMatch(eth_dst=eth_pkt.src), [
                                  ofp_parser.OFPActionOutput(in_port)], priority=1, hard_timeout=10)
                    self.add_flow(dp, ofp_parser.OFPMatch(eth_dst=eth_pkt.dst), [
                                  ofp_parser.OFPActionOutput(out_port)], priority=1, hard_timeout=10)
                else:
                    out_port = ofp.OFPP_FLOOD
                    del self.ports_to_mac_addresses[eth_pkt.dst]

            # Send to all ports
            else:
                out_port = ofp.OFPP_FLOOD

            # Send the packet
            self.send_packet(dp, out_port, pkt)

        # Packet is from a router
        else:
            arp_pkt: arp.arp = pkt.get_protocol(arp.arp)
            ip_pkt: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)

            # Packet is an ARP request
            if arp_pkt is not None:
                print(dp.id, datetime.now(), "ARP",
                      arp_pkt.src_ip, arp_pkt.dst_ip)

                # Add MAC to IP-MAC translation table.
                self.mac_addresses[IPv4Address(arp_pkt.src_ip)] = (
                    arp_pkt.src_mac, datetime.now() + timedelta(seconds=KNOWLEDGE_TTL))

                # ARP request to router IP
                if arp_pkt.opcode == arp.ARP_REQUEST and IPv4Address(arp_pkt.dst_ip) == ROUTER_IP[in_port]:
                    response_pkt = packet.Packet()
                    response_pkt.add_protocol(
                        ethernet.ethernet(
                            src=ROUTER_MAC[in_port], dst=eth_pkt.src, ethertype=eth_pkt.ethertype)
                    )
                    response_pkt.add_protocol(
                        arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=ROUTER_MAC[in_port], src_ip=ROUTER_IP[in_port],
                                dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
                    )
                    self.send_packet(dp, in_port, response_pkt)

            # Packet is an IP packet
            elif ip_pkt is not None:
                source = IPv4Address(ip_pkt.src)
                destination = IPv4Address(ip_pkt.dst)

                print(dp.id, datetime.now(), "IP", source, destination)

                ip_pkt.ttl -= 1
                if ip_pkt.ttl == 0:
                    return # "Time exceeded" response not implemented for brevity.

                src_port, src_subnet = next(
                    filter(lambda item: source in item[1], SUBNETS.items()))
                dst_port, dst_subnet = next(
                    filter(lambda item: destination in item[1], SUBNETS.items()))
                icmp_pkt: icmp.icmp = pkt.get_protocol(icmp.icmp)

                # Add MAC to IP-MAC translation table.
                if source in SUBNETS[in_port]:
                    self.mac_addresses[source] = (
                        eth_pkt.src, datetime.now() + timedelta(seconds=KNOWLEDGE_TTL))

                if eth_pkt.dst != ROUTER_MAC[src_port]:
                    return  # This packet is not meant for the router.
                elif {src_port, dst_port} == {2, 3}:
                    return  # Deny communication between external and datacenter hosts
                elif {src_port, dst_port} == {1, 3} and icmp_pkt is not None and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    return  # Deny pings between external hosts and workstations
                    # Pings to datacenter hosts already excluded

                # ICMP request to the router
                if destination == ROUTER_IP[dst_port]:
                    icmp_pkt: icmp.icmp = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt is None or icmp_pkt.type != icmp.ICMP_ECHO_REQUEST or source not in dst_subnet:
                        return

                    ip_pkt.src, ip_pkt.dst = ip_pkt.dst, ip_pkt.src
                    eth_pkt.src, eth_pkt.dst = eth_pkt.dst, eth_pkt.src
                    icmp_pkt.type = icmp.ICMP_ECHO_REPLY
                    icmp_pkt.csum = 0
                    ip_pkt.csum = 0
                    self.send_packet(dp, dst_port, pkt)

                else:
                    if destination in self.mac_addresses:
                        dst_mac, deadline = self.mac_addresses[destination]

                        if deadline >= datetime.now():
                            self.add_flow(dp, ofp_parser.OFPMatch(
                                eth_type=ethernet.ether.ETH_TYPE_IP,
                                # Forward all messages from the source subnet since the firewall treats
                                # it as one.
                                ipv4_src=(src_subnet.network_address,
                                          src_subnet.netmask),
                                ipv4_dst=destination
                            ), [
                                ofp_parser.OFPActionDecNwTtl(),  # Automatically discards messages with TTL==0
                                ofp_parser.OFPActionSetField(
                                    eth_src=ROUTER_MAC[dst_port]),
                                ofp_parser.OFPActionSetField(eth_dst=dst_mac),
                                ofp_parser.OFPActionOutput(dst_port),
                            ], hard_timeout=10)
                            eth_pkt.dst = dst_mac
                        else:
                            eth_pkt.dst = BROADCAST_MAC
                            del self.mac_addresses[destination]
                    else:
                        eth_pkt.dst = BROADCAST_MAC

                    eth_pkt.src = ROUTER_MAC[dst_port]
                    self.send_packet(dp, dst_port, pkt)

                    if eth_pkt.dst == BROADCAST_MAC:
                        # We don't know the destination MAC address yet. Broadcast the message
                        # in the hope that it's useful to someone, and make an ARP request to be prepared next time.
                        arp_request_pkt = packet.Packet()
                        arp_request_pkt.add_protocol(
                            ethernet.ethernet(
                                src=ROUTER_MAC[dst_port], ethertype=ethernet.ether.ETH_TYPE_ARP)
                        )
                        arp_request_pkt.add_protocol(
                            arp.arp(
                                src_mac=ROUTER_MAC[dst_port], src_ip=ROUTER_IP[dst_port], dst_ip=destination)
                        )
                        self.send_packet(dp, dst_port, arp_request_pkt)
