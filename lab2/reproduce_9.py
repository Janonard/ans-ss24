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

# Setup for Jellyfish
num_servers = 686
num_switches = 245
num_ports = 14

jf_topo = topo.Jellyfish(num_servers, num_switches, num_ports)

ft_topo = topo.Fattree(14)

for (source, sink) in tqdm(list(product(ft_topo.servers, ft_topo.servers))):
    k_shortest_paths = ft_topo.k_shortest_paths(source, sink, 8)
