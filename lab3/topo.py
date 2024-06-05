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
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
from tqdm import tqdm
from multiprocessing import Pool
from ipaddress import IPv4Address
import json
import socketserver
import threading

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3


class ReportingRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ReportingRouter, self).__init__(*args, **kwargs)
        self.topo_net = Fattree(4)

        self.data_collection_state = None
        self.collection_done = threading.Event()
        self.pre_port_data = dict()
        self.post_port_data = dict()
        self.missing_switches_for_data = list()

        router = self

        class DataRequestHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                text = self.request[0]
                if text == b"Start":
                    router.data_collection_state = "Start"
                elif text == b"Stop":
                    router.data_collection_state = "Stop"
                else:
                    return
                
                router.collection_done.clear()
                router.missing_switches_for_data = list()
                for switch in router.topo_net.switches:

                    dp: Datapath = switch.datapath
                    if dp is None:
                        continue
                    router.missing_switches_for_data.append(
                        IPv4Address(dp.id))

                    ofproto = dp.ofproto
                    parser = dp.ofproto_parser

                    # Send a request for stats
                    dp.send_msg(parser.OFPPortStatsRequest(
                        dp, 0, ofproto.OFPP_ANY))
                
                router.collection_done.wait()
                self.request[1].sendto(b"Done", self.client_address)

        def serve_data_requests():
            with socketserver.UDPServer(("localhost", 4711), DataRequestHandler) as dataserver:
                dataserver.serve_forever()

        self.thread_pool = ThreadPoolExecutor()
        self.thread_pool.submit(serve_data_requests)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def handle_ports_stats_reply(self, ev):
        dp: Datapath = ev.msg.datapath
        ip = IPv4Address(dp.id)
        self.missing_switches_for_data.remove(ip)

        ip = str(ip)
        data = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}
        if self.data_collection_state == "Start":
            self.pre_port_data[ip] = data
        else:
            self.post_port_data[ip] = data

        if len(self.missing_switches_for_data) == 0:
            self.collection_done.set()
            if self.data_collection_state == "Stop":
                port_data = dict()
                for ip in self.post_port_data.keys():
                    port_data[ip] = dict()
                    for port in self.post_port_data[ip].keys():
                        port_data[ip][port] = self.post_port_data[ip][port] - self.pre_port_data[ip][port]
                with open("sent_bytes.json", "w") as out_file:
                    json.dump(port_data, out_file)

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


class Edge:
    """
    Class for an edge in the graph
    """

    def __init__(self):
        self.lnode = None
        self.lport = None

        self.rnode = None
        self.rport = None

    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)

        self.lnode = None
        self.lport = None

        self.rnode = None
        self.rport = None


class Node:
    """
    Class for a node in the graph
    """

    def __init__(self, id, type, ip):
        self.edges = []
        self.visited = False
        self.__id__ = id
        self.__type__ = type
        self.__ip__ = ip
        self.__node_hash__ = hash(self.label)
        self.__datapath__ = None

    # Add an edge connected to another node
    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    # Remove an edge from the node
    def remove_edge(self, edge):
        if edge.lnode is self:
            edge.rnode.edges.remove(edge)
        elif edge.rnode is self:
            edge.lnode.edges.remove(edge)
        else:
            raise Exception("Node not part of this edge")
        self.edges.remove(edge)

    @property
    def id(self):
        return self.__id__

    @property
    def type(self):
        return self.__type__

    @property
    def ip(self):
        return self.__ip__

    @property
    def datapath(self):
        return self.__datapath__

    @datapath.setter
    def datapath(self, datapath):
        self.__datapath__ = datapath

    @property
    def label(self):
        return f"{self.type}{self.id}"

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False

    @property
    def neighbors(self):
        for edge in self.edges:
            if edge.lnode is self:
                yield edge.rnode
            elif edge.rnode is self:
                yield edge.lnode
            else:
                raise Exception("Illegal edge data")

    def __eq__(self, value: object) -> bool:
        return self.__node_hash__ == value.__node_hash__

    def __hash__(self) -> int:
        return self.__node_hash__

    def __repr__(self) -> str:
        return f"Node {self.label}"


class Topology(object):
    """
    Generalized network topology
    """

    def __init__(self):
        self.servers = []
        self.switches = []

    def to_dot(self):
        node_lines = []
        edge_lines = []
        added_edges = set()
        for node in chain(self.servers, self.switches):
            node_lines.append(
                f"\t{node.label} [ip=\"{node.ip}\", dp=\"{node.datapath}\"];")
            for edge in node.edges:
                if edge not in added_edges:
                    added_edges.add(edge)
                    edge_lines.append(
                        f"\t{edge.lnode.label} -- {edge.rnode.label} [lport={edge.lport}, rport={edge.rport}];")
        return "graph {\n" + "\n".join(node_lines) + "\n" + "\n".join(edge_lines) + "\n}"

    def node_by_ip(self, ip: str) -> Node:
        for node in chain(self.servers, self.switches):
            if node.ip == ip:
                return node

    def sanity_checks(self):
        # Server and Switch lists are clean
        assert (all(s.type == "h" for s in self.servers))
        assert (all(s.type == "s" for s in self.switches))

        for node in chain(self.servers, self.switches):
            for edge in node.edges:
                # All nodes are actually part of their edges
                assert (edge.lnode is node or edge.rnode is node)

                # Edges don't lead out of the topology
                assert (edge.lnode in self.servers or edge.lnode in self.switches)
                assert (edge.rnode in self.servers or edge.rnode in self.switches)

        # Each server is connected to one, and only one, switch
        for s in self.servers:
            assert (len(s.edges) == 1)
            e = s.edges[0]
            if e.lnode is s:
                assert (e.rnode.type == "s")
            else:
                assert (e.lnode.type == "s")

        # The topology is connected (do a BFS)
        missing_nodes = set(chain(self.servers, self.switches))
        queue = [self.servers[0]]
        while len(queue) > 0:
            current_node = queue.pop(0)
            for edge in current_node.edges:
                other_node = edge.lnode if edge.rnode is current_node else edge.rnode
                if other_node in missing_nodes:
                    queue.append(other_node)
                    missing_nodes.remove(other_node)
        assert (len(missing_nodes) == 0)

    def single_source_shortest_paths(self, source, sink=None):
        """
        Run breadth-first search to find the shortest paths to all (other) servers.
        """
        shortest_paths: dict[Node, list[Node]] = {source: [source]}
        queue: list[Node] = [source]

        for node in chain(self.servers, self.switches):
            node.visited = False

        while len(queue) != 0:
            current_node = queue.pop(0)
            current_path = shortest_paths[current_node]

            for edge in current_node.edges:
                neighbor = edge.lnode if edge.lnode is not current_node else edge.rnode

                if not neighbor.visited:
                    shortest_paths[neighbor] = current_path + [neighbor]
                    if neighbor is sink:
                        return shortest_paths
                    neighbor.visited = True
                    queue.append(neighbor)

        return shortest_paths

    def all_server_pairs_shortest_paths(self):
        shortest_paths = dict()
        for source_server in tqdm(self.servers):
            source_server_shortest_paths = self.single_source_shortest_paths(
                source_server)
            for dest_server in self.servers:
                shortest_paths[(source_server, dest_server)
                               ] = source_server_shortest_paths[dest_server]
        return shortest_paths

    def k_shortest_paths(self, source, sink, k):
        A: list[list[Node]] = [self.single_source_shortest_paths(source, sink)[
            sink]]
        B: list[list[Node]] = []

        for k in range(1, k):
            for i in range(0, len(A[k-1]) - 2):
                spur_node = A[k-1][i]
                root_path = A[k-1][0:i]

                removed_edges: list[tuple[Node, Node]] = []

                for p in A:
                    if p[0:i] == root_path and p[i] == spur_node:
                        next_node_in_p = p[i+1]
                        removed_edges.append((spur_node, next_node_in_p))
                        for edge in spur_node.edges:
                            if next_node_in_p in [edge.lnode, edge.rnode]:
                                spur_node.remove_edge(edge)
                                break

                for root_path_node in root_path:
                    # Removing all edges towards a node is as good as removing it from the graph.
                    for edge in root_path_node.edges:
                        removed_edges.append((edge.lnode, edge.rnode))
                        root_path_node.remove_edge(edge)

                shortest_paths = self.single_source_shortest_paths(
                    spur_node, sink)
                if sink in shortest_paths:
                    B.append(root_path + shortest_paths[sink])

                for (lnode, rnode) in removed_edges:
                    lnode.add_edge(rnode)

            if len(B) == 0:
                break
            B.sort(key=lambda path: len(path))
            A.append(B.pop(0))

        return A

    def __all_k_shortest_paths_kernel__(self, pair):
        i_source, i_sink, k = pair
        source = self.servers[i_source]
        sink = self.servers[i_sink]

        forward_paths = self.k_shortest_paths(source, sink, k)
        reverse_paths = []
        for p in forward_paths:
            reverse_path = list(p)
            reverse_path.reverse()
            reverse_paths.append(reverse_path)
        return i_source, i_sink, forward_paths, reverse_paths

    def all_k_shortest_paths(self, k, pairs=None, parallel=True):
        paths = dict()

        def create_input_feed():
            if pairs is None:
                for i_source in range(0, len(self.servers)):
                    for i_sink in range(i_source, len(self.servers)):
                        yield (i_source, i_sink, k)
            else:
                for (i_source, i_sink) in pairs:
                    yield (i_source, i_sink, k)
        input_feed = tqdm(list(create_input_feed()))

        with Pool() as pool:
            if parallel:
                paths_from_source = pool.imap_unordered(
                    self.__all_k_shortest_paths_kernel__, input_feed, 16)
            else:
                paths_from_source = map(
                    self.__all_k_shortest_paths_kernel__, input_feed)
            for i_source, i_sink, forward_paths, reverse_paths in paths_from_source:
                paths[(self.servers[i_source], self.servers[i_sink])
                      ] = forward_paths
                paths[(self.servers[i_sink], self.servers[i_source])
                      ] = reverse_paths
        return paths


class Fattree(Topology):
    """
    Implementation of the fat tree topology.
    """

    def __init__(self, num_ports):
        super().__init__()
        self.generate(num_ports)

    def generate(self, num_ports):

        num_ports_half = int(num_ports / 2)
        self.switches = []
        self.edges = []

        # Create core switches
        for i in range(0, num_ports_half):
            for j in range(0, num_ports_half):
                self.switches.append(
                    Node(len(self.switches), "s", IPv4Address(f"10.{num_ports}.{i+1}.{j+1}")))

        # Create pods
        for pod in range(0, num_ports):

            for i in range(0, num_ports_half):
                # Create (k/2) edge switches
                self.switches.append(
                    Node(len(self.switches), "s", IPv4Address(f"10.{pod}.{i}.1")))

                for j in range(0, num_ports_half):
                    # Add (k/2) servers per edge switch
                    self.servers.append(
                        Node(len(self.servers), "h", IPv4Address(f"10.{pod}.{i}.{j+2}")))

                    # Add edge: edge - server
                    self.edges.append(
                        self.switches[-1].add_edge(self.servers[-1]))

            for i in range(0, num_ports_half):
                # Create (k/2) aggregation switches
                self.switches.append(
                    Node(len(self.switches), "s", IPv4Address(f"10.{pod}.{i+num_ports_half}.1")))

                # Add edges (cartesian product): edge - aggregation
                for edge_switch in self.switches[-num_ports_half - 1 - i: -1 - i]:
                    self.edges.append(edge_switch.add_edge(self.switches[-1]))

                # Add edges: core - aggregation
                for core_switch in self.switches[i * num_ports_half: (i + 1) * num_ports_half]:
                    self.edges.append(core_switch.add_edge(self.switches[-1]))


if __name__ == "__main__":
    topo_fattree = Fattree(4)
    topo_fattree.sanity_checks()
    print(topo_fattree.to_dot())
