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
from matplotlib import pyplot

# Same setup for Jellyfish and fat-tree
num_servers = 686
num_switches = 245
num_ports = 14


def make_connectivity_stats(topo):
    paths = topo.all_server_pairs_shortest_paths()
    stats = dict()
    for path in paths.values():
        length = len(path) - 1
        if length not in stats:
            stats[length] = 1
        else:
            stats[length] += 1
    del stats[0]
    n_pairs = sum(stats.values())
    return {length: count / n_pairs for (length, count) in stats.items()}


print("Computing the stats for the fat tree...")
ft_topo = topo.Fattree(14)
ft_stats = make_connectivity_stats(ft_topo)
print("Done!")
print()

print("Computing the stats for Jellyfish...")
mean_jl_stats = dict()
for i in range(0, 10):
    jl_topo = topo.Jellyfish(686, 245, 14)
    jl_stats = make_connectivity_stats(jl_topo)
    for (length, count) in jl_stats.items():
        if length not in mean_jl_stats:
            mean_jl_stats[length] = [count]
        else:
            mean_jl_stats[length].append(count)
jl_stats = {length: sum(count) / len(count)
            for (length, count) in mean_jl_stats.items()}
print("Done!")

pyplot.figure()
pyplot.ylim((0, 1.0))
pyplot.yticks([i / 10.0 for i in range(0, 11)])
pyplot.grid(True, linestyle="--")
pyplot.ylabel("Fraction of Server Pairs")
pyplot.xlabel("Path length")
pyplot.bar([length + 0.2 for length in ft_stats.keys()],
           list(ft_stats.values()), width=0.4, label="Fat-tree")
pyplot.bar([length - 0.2 for length in jl_stats.keys()],
           list(jl_stats.values()), width=0.4, label="Jellyfish")
pyplot.legend()
pyplot.savefig("lab2/figure_1c.pdf")
