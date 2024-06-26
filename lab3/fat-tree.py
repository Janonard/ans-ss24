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
import random
import socket
import re
import json

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

import topo


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):
        Topo.__init__(self)

        # Create a node for each switch/server
        nodes = dict()
        for device in ft_topo.switches:
            nodes[device.label] = self.addSwitch(
                device.label, dpid=hex(int(device.ip))[2:])
        for device in ft_topo.servers:
            nodes[device.label] = self.addHost(
                device.label, ip=str(device.ip), prefixLen=8)

        # Create a link for each edge
        for edge in ft_topo.edges:
            self.addLink(nodes[edge.lnode.label],
                         nodes[edge.rnode.label], bw=15, delay='5ms')


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True,
                  switch=OVSKernelSwitch, link=TCLink)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)
    controller_data_server = socket.socket(
        socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_DGRAM)

    info('*** Starting network ***\n')
    net.start()
    net.pingAll()

    pairs = [("h0", "h8"), ("h2", "h10"), ("h4", "h12"), ("h6", "h14")]
    pairs = [(net.get(a_node), net.get(b_node)) for (a_node, b_node) in pairs]

    info('*** Running Benchmark ***\n')

    controller_data_server.sendto(b"Start", ("localhost", 4711))
    assert controller_data_server.recv(4) == b"Done"

    with ThreadPoolExecutor(max_workers=len(graph_topo.switches)) as executor:
        executor.map(lambda pair: net.iperf(hosts=pair, seconds=30), pairs)

    controller_data_server.sendto(b"Stop", ("localhost", 4711))
    assert controller_data_server.recv(4) == b"Done"

    info('*** Stopping network ***\n')
    net.stop()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)
