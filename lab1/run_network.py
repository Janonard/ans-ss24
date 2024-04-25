#!/bin/env python3
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

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

        hosts = {
            "h1": {"ip": "10.0.1.2/24", "gateway": "10.0.1.1"},
            "h2": {"ip": "10.0.1.3/24", "gateway": "10.0.1.1"},
            "ser": {"ip": "10.0.2.2/24", "gateway": "10.0.2.1"},
            "ext": {"ip": "192.168.1.123/24", "gateway": "192.168.1.1"}
        }

        nodes = dict()
        for (name, data) in hosts.items():
            nodes[name] = self.addHost(name,
                                            ip=data["ip"],
                                            defaultRoute=f"via {data['gateway']}"
                                            )

        for name in ["s1", "s2", "s3"]:
            nodes[name] = self.addSwitch(name)
        for (a, b) in [("h1", "s1"), ("h2", "s1"), ("s1", "s3"), ("s3", "ext"), ("s3", "s2"), ("s2", "ser")]:
            self.addLink(nodes[a], nodes[b], bw=15, delay='10ms')

topos = {'network': (lambda: NetworkTopo())}

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()