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

import topo
from tqdm import tqdm
from itertools import product, chain
from matplotlib import pyplot
from random import shuffle, choice

# Sanity check for corretness
ft_topo = topo.Fattree(4)
source = ft_topo.servers[0]
sink = ft_topo.servers[-1]
paths = ft_topo.k_shortest_paths(source, sink, 8)
assert len(paths) == 8
assert len(paths[0]) == 7
assert len(paths[1]) == 7
assert len(paths[2]) == 7
assert len(paths[3]) == 7
assert len(paths[4]) == 9
assert len(paths[5]) == 9
assert len(paths[6]) == 9
assert len(paths[7]) == 9

for p in paths:
    assert p[0] == source and p[-1] == sink
    for i in range(1, len(p)):
        assert p[i-1] in p[i].neighbors


# Setup for Jellyfish
num_servers = 686
num_switches = 245
num_ports = 14

if __name__ == "__main__":
    jf_topo = topo.Jellyfish(num_servers, num_switches, num_ports)

    sources = list(range(len(jf_topo.servers)))
    sinks = list(sources)
    shuffle(sinks)

    k_shortest_links = dict()
    ecmp_8_links = dict()
    ecmp_64_links = dict()

    for ((source, sink), paths) in jf_topo.all_k_shortest_paths(64, pairs=zip(sources, sinks)).items():
        minimal_length = len(paths[0])
        minimal_paths = [path for path in paths if len(path) == minimal_length]
        ecmp_8_paths = minimal_paths[0:8]
        ecmp_64_paths = minimal_paths[0:64]

        k_shortest_paths = paths[0:8]

        for path_list, link_dict in [(ecmp_8_paths, ecmp_8_links), (ecmp_64_paths, ecmp_64_links), (k_shortest_paths, k_shortest_links)]:
            link_set = set()
            for path in path_list:
                for i in range(1, len(path) - 2):
                    link = (path[i], path[i+1])
                    if link in link_set:
                        continue
                    link_set.add(link)
                    if link not in link_dict:
                        link_dict[link] = 1
                    else:
                        link_dict[link] += 1

    # Create the figure
    pyplot.figure()
    pyplot.grid(True, linestyle="--")
    pyplot.ylabel("#Distinct Paths Link is on")
    pyplot.xlabel("Rank of Link")
    pyplot.plot(sorted(k_shortest_links.values()), label="8 Shortest Paths")
    pyplot.plot(sorted(ecmp_64_links.values()), label="64-way ECMP")
    pyplot.plot(sorted(ecmp_8_links.values()), label="8-way ECMP")
    pyplot.legend()
    pyplot.savefig("lab2/figure_9.pdf")
    pyplot.show()
