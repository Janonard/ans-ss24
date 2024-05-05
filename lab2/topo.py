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
        self.id = id
        self.type = type

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
    def label(self):
        return f"{self.type}{self.id}"

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False


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
    Implementation of the fat tree topology
    """

    def __init__(self, num_ports):
        super().__init__()
        self.generate(num_ports)

    def generate(self, num_ports):

        # TODO: code for generating the fat-tree topology
        pass


if __name__ == "__main__":
    topo = Jellyfish(686, 245, 14)
    topo.sanity_checks()
    with open("jellyfish.dot", mode="w") as f:
        f.write(topo.to_dot())
