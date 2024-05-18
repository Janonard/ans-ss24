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
from random import sample, choice
from itertools import cycle, chain
from tqdm import tqdm
from itertools import product
import uuid
from multiprocessing import Pool


class Edge:
    """
    Class for an edge in the graph
    """

    def __init__(self):
        self.lnode = None
        self.rnode = None

    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None


class Node:
    """
    Class for a node in the graph
    """

    def __init__(self, id, type):
        self.edges = []
        self.visited = False
        self.__id__ = id
        self.__type__ = type
        self.__node_hash__ = hash(self.label)

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
            node_lines.append(f"\t{node.label};")
            for edge in node.edges:
                if edge not in added_edges:
                    added_edges.add(edge)
                    edge_lines.append(
                        f"\t{edge.lnode.label} -- {edge.rnode.label};")
        return "graph {\n" + "\n".join(node_lines) + "\n" + "\n".join(edge_lines) + "\n}"

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
        shortest_paths: dict[Node, tuple[int, list[Node]]] = {source: [source]}
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


class Jellyfish(Topology):
    """
    Implementation of the jellyfish topology
    """

    def __init__(self, num_servers, num_switches, num_ports):
        super().__init__()
        self.generate(num_servers, num_switches, num_ports)

    def generate(self, num_servers, num_switches, num_ports):
        assert num_ports > num_servers / num_switches, \
            f"{num_ports} ports are not enough support {num_servers} servers with {num_switches} switches"

        self.servers = [Node(i_server, "h")
                        for i_server in range(0, num_servers)]
        self.switches = [Node(i_switch, "s")
                         for i_switch in range(0, num_switches)]

        # Allocate servers to switches in a round-robin fashion
        for server, switch in zip(self.servers, cycle(self.switches)):
            server.add_edge(switch)

        # Switches that still have free ports
        free_switches = list(self.switches)
        # Links that we made, later used for uniform sampling
        made_links = list()

        while len(free_switches) >= 2:
            # Sample from all switch tuples
            i_switch_a, i_switch_b = sample(range(0, len(free_switches)), 2)
            switch_a, switch_b = free_switches[i_switch_a], free_switches[i_switch_b]

            # Create the link
            made_links.append(switch_a.add_edge(switch_b))

            # Remove switches from list of free switches if fully occupied
            if len(switch_a.edges) == num_ports:
                del free_switches[i_switch_a]
                if i_switch_b > i_switch_a:
                    # Update the index of the second switch
                    i_switch_b -= 1

            if len(switch_b.edges) == num_ports:
                del free_switches[i_switch_b]

        if len(free_switches) == 1:
            lonely_switch = free_switches[0]

            # Include the lonely switch in the network until it has only one port left.
            while num_ports - len(lonely_switch.edges) > 1:
                i_link = choice(range(0, len(made_links)))

                link_to_break = made_links[i_link]
                lnode = link_to_break.lnode
                rnode = link_to_break.rnode

                lnode.remove_edge(link_to_break)
                lnode.add_edge(lonely_switch)
                lonely_switch.add_edge(rnode)

                # Do not add the new link to the list! We don't want self-edges!
                del made_links[i_link]


class Fattree(Topology):
    """
    Implementation of the fat tree topology.
    """

    def __init__(self, num_ports):
        super().__init__()
        self.generate(num_ports)

    def generate(self, num_ports):

        num_ports_half = int(num_ports / 2)

        # Create core switches
        self.switches = [Node(i, "s") for i in range(0, num_ports_half ** 2)]

        # Create pods
        for pod in range(0, num_ports):

            for i in range(0, num_ports_half):
                # Create (k/2) edge switches
                self.switches.append(Node(len(self.switches), "s"))

                for j in range(0, num_ports_half):
                    # Add (k/2) servers per edge switch
                    self.servers.append(Node(len(self.servers), "h"))

                    # Add edge: edge - server
                    self.switches[-1].add_edge(self.servers[-1])

            for i in range(0, num_ports_half):
                # Create (k/2) aggregation switches
                self.switches.append(Node(len(self.switches), "s"))

                # Add edges (cartesian product): edge - aggregation
                for edge_switch in self.switches[-num_ports_half - 1 - i: -1 - i]:
                    edge_switch.add_edge(self.switches[-1])

                # Add edges: core - aggregation
                for core_switch in self.switches[i * num_ports_half: (i + 1) * num_ports_half]:
                    core_switch.add_edge(self.switches[-1])


if __name__ == "__main__":
    topo_jellyfish = Jellyfish(686, 245, 14)
    topo_jellyfish.sanity_checks()
    with open("jellyfish.dot", mode="w") as f:
        f.write(topo_jellyfish.to_dot())

    topo_fattree = Fattree(14)
    topo_fattree.sanity_checks()
    with open("fattree.dot", mode="w") as f:
        f.write(topo_fattree.to_dot())
