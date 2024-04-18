#!/usr/bin/env python3
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
from mininet.link import TCLink
from mininet.net import Mininet

class BridgeTopo(Topo):
    "Create a bridge-like customized network topology according to Figure 1 in the lab0 description."

    def __init__(self):

        Topo.__init__(self)

        self.h1 = self.addHost("h1")
        self.h2 = self.addHost("h2")
        self.h3 = self.addHost("h3")
        self.h4 = self.addHost("h4")

        self.s1 = self.addSwitch("s1")
        self.s2 = self.addSwitch("s2")

        self.e1 = self.addLink(self.h1, self.s1, bw=15, delay='10ms')
        self.e2 = self.addLink(self.h2, self.s1, bw=15, delay='10ms')
        self.e3 = self.addLink(self.h3, self.s2, bw=15, delay='10ms')
        self.e4 = self.addLink(self.h4, self.s2, bw=15, delay='10ms')
        self.e5 = self.addLink(self.s1, self.s2, bw=20, delay='45ms')

topos = {'bridge': (lambda: BridgeTopo())}
