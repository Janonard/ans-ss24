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

from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os

NUM_WORKERS = 2 # TODO: Make sure your program can handle larger values

class SMLTopo(Topo):
    def __init__(self, n_workers, **opts):
        Topo.__init__(self, **opts)

        self.workers = [
            self.addHost(f"w{i}", ip=f"10.0.0.{i + 1}", prefixLen=8, mac=f"08:00:00:00:00:{i+1:02d}")
            for i in range(n_workers)
        ]

        self.switch = self.addSwitch("s", dpid="1")

        for worker in self.workers:
            self.addLink(self.switch, worker)

def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    Redirects output to logs/<worker_name>.log (see lib/worker.py, Log())
    This function assumes worker i is named 'w<i>'. Feel free to modify it
    if your naming scheme is different
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).sendCmd('python worker.py %d > %s 2> %s.err' % (i, log_file(i), log_file(i)))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()

def RunControlPlane(net):
    """
    One-time control plane configuration
    """
    switch = net.get("s")

    # Ethernet forwarding configuration
    switch.addMulticastGroup(mgid=1, ports=range(1, NUM_WORKERS+1))
    switch.insertTableEntry(
        table_name="TheIngress.decide_eth_forward",
        match_fields={"hdr.eth.dstAddr": "08:00:00:00:00:01"},
        action_name="TheIngress.forward_eth_packet",
        action_params={"out_port": 1}
    )
    switch.insertTableEntry(
        table_name="TheIngress.decide_eth_forward",
        match_fields={"hdr.eth.dstAddr": "08:00:00:00:00:02"},
        action_name="TheIngress.forward_eth_packet",
        action_params={"out_port": 2}
    )
    switch.insertTableEntry(
        table_name="TheIngress.decide_eth_forward",
        match_fields={"hdr.eth.dstAddr": "ff:ff:ff:ff:ff:ff"},
        action_name="TheIngress.broadcast_eth_packet"
    )

    # SML result broadcast configuration
    switch.addMulticastGroup(mgid=2, ports=range(1, NUM_WORKERS+1))
    switch.insertTableEntry(
        table_name="TheEgress.allreduce_broadcast",
        match_fields={"standard_metadata.egress_rid": 0},
        action_name="TheEgress.write_allreduce_broadcast_headers",
        action_params={
            "hardware_address": "08:00:00:00:00:01",
            "protocol_address": "10.0.0.1"
        }
    )
    switch.insertTableEntry(
        table_name="TheEgress.allreduce_broadcast",
        match_fields={"standard_metadata.egress_rid": 1},
        action_name="TheEgress.write_allreduce_broadcast_headers",
        action_params={
            "hardware_address": "08:00:00:00:00:02",
            "protocol_address": "10.0.0.2"
        }
    )

topo = SMLTopo(NUM_WORKERS)
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()
net.run_workers()
CLI(net)
net.stop()