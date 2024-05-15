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
from itertools import product
from matplotlib import pyplot

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
    # TODO: change to jellyfish
    jf_topo = topo.Jellyfish(num_servers, num_switches, num_ports)
    ft_topo = topo.Fattree(4)
    paths = ft_topo.all_k_shortest_paths(8)

    # Extract number of distinct paths per link
    list_of_paths = [
        item 
        for sublist in paths.values() 
        for item in sublist 
        if len(item) > 1
    ]

    links = []
    for path in list_of_paths:
        links += [[str(path[i]), str(path[i+1])] for i in range(len(path) - 1)]

    number_of_paths = {}
    for link in links:
        link = tuple(link)
        if link in number_of_paths:
            number_of_paths[link] += 1
        else:
            number_of_paths[link] = 1

    sorted_number_of_paths = sorted(number_of_paths.values())

    # Create the figure
    pyplot.figure()
    pyplot.xlim((0, len(sorted_number_of_paths)))
    #pyplot.ylim((0, 18))
    #pyplot.yticks([i * 2 for i in range(0, 9)])
    pyplot.grid(True, linestyle="--")
    pyplot.ylabel("#Distinct Paths Link is on")
    pyplot.xlabel("Rank of Link")
    pyplot.plot(list(range(0, len(sorted_number_of_paths))), 
                sorted_number_of_paths, label="8 Shortest Paths")
    pyplot.legend()
    pyplot.show()
    pyplot.savefig("lab2/figure_9.pdf")
