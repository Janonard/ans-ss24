/*
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
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
typedef bit<8> worker_id_t; /*< Worker IDs */

const worker_id_t n_workers = 8;
const mac_addr_t accumulator_mac = 0x080000000101;

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16> etherType;
}

header sml_t {
  worker_id_t rank;
  bit<2048> chunk;
}

struct headers {
  ethernet_t eth;
  sml_t sml;
}

struct metadata { /* empty */ }

parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  state start {
    packet.extract(hdr.eth);
    transition select(hdr.eth.etherType) {
      0x4200: parse_sml;
      default: accept;
    }
  }

  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
}


tuple<bool, bool> atomic_enter_bitmap(register<bit<64>> bitmap, in worker_id_t i_worker) {
  bit<64> old_bitmap_value;
  bit<64> new_bitmap_value;
  @atomic {
    bitmap.read(old_bitmap_value, 0);

    new_bitmap_value = old_bitmap_value | (64w1 << i_worker);

    bitmap.write(0, new_bitmap_value);
  };
  bool valid_entry = (old_bitmap_value & (64w1 << i_worker)) == 0;
  bool last_entry = new_bitmap_value == ((64w1 << n_workers) - 1); 
  return { valid_entry, last_entry };
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

  action forward_eth_packet(bit<9> out_port) {
    standard_metadata.egress_spec = out_port;
  }

  action broadcast_eth_packet() {
    standard_metadata.mcast_grp = 1;
  }

  action drop_eth_packet() {
    mark_to_drop(standard_metadata);
  }

  table decide_eth_forward {
    key = {
      hdr.eth.dstAddr: exact;
    }
    actions = {
      forward_eth_packet;
      broadcast_eth_packet;
      drop_eth_packet;
    }
    default_action = drop_eth_packet();
  }

  register<bit<64>>(1) arrival_bitmap;
  register<bit<2048>>(1) accumulated_chunk;
  register<bit<64>>(1) completion_bitmap;

  apply {
    if (hdr.eth.isValid() && hdr.eth.dstAddr == accumulator_mac && hdr.sml.isValid()) {
      // Check that this is the first packet from this worker.
      tuple<bool, bool> arrival_result = atomic_enter_bitmap(arrival_bitmap, hdr.sml.rank);
      bool first_arrival = arrival_result[0];
      if (!first_arrival) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Accumulate
      @atomic {
        bit<2048> old_value;
        accumulated_chunk.read(old_value, 0);
        bit<2048> new_value = old_value + hdr.sml.chunk;
        accumulated_chunk.write(0, new_value);
      }

      // Check whether this chunk is the last chunk to be accumulated.
      tuple<bool, bool> accum_result = atomic_enter_bitmap(completion_bitmap, hdr.sml.rank);
      bool last_accumalation = accum_result[1];
      if (!last_accumalation) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Load result and reset memory.
      // No need to use atomics here since (a) single extern functions are atomic per definition and
      // (b) there is only one thread in this section anyways.
      accumulated_chunk.read(hdr.sml.chunk, 0);
      completion_bitmap.write(0, 0);
      accumulated_chunk.write(0, 0);
      arrival_bitmap.write(0, 0);

      // Broadcast result
      standard_metadata.mcast_grp = 2;
    } else if (hdr.eth.isValid()) {
      // Normal packet forwarding
      decide_eth_forward.apply();

    } else {
      mark_to_drop(standard_metadata);
    }
  }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  apply {
    if (hdr.sml.isValid() && standard_metadata.mcast_grp == 2) {
      // We are broadcasting an accumulation result.
      hdr.sml.rank = 0xff;
      hdr.eth.srcAddr = accumulator_mac;
      hdr.eth.dstAddr = 0xffffffffffff;
    }
  }
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
}

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.eth);
    packet.emit(hdr.sml);
  }
}

V1Switch(
  TheParser(),
  TheChecksumVerification(),
  TheIngress(),
  TheEgress(),
  TheChecksumComputation(),
  TheDeparser()
) main;