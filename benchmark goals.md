# Metrics:
* Bandwidth per Pair

# Benchmark/Situations
* Random pairs
    * Evenly spread utilization of core and aggregation switches
    * High throughput per link, depending on class
    * Goal: 15 Mbit/s for every pair
* One to all hosts
    * Evenly spread utilization of core and aggregation switches
* One to all pods
    * E.g. h0 iperfs to h4, h8, and h12
    * Cumulative throughput should be local link throughput