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
typedef bit<32> ipv4_addr_t; /*< IPv4 address */
typedef bit<8> worker_id_t; /*< Worker IDs */

const worker_id_t n_workers = 2;
const mac_addr_t accumulator_mac = 0x080000000101; // 08:00:00:00:01:01
const ipv4_addr_t accumulator_ip = 0x0a000101; // 10.0.1.1
const bit<16> accumulator_port = 0x4200;

header ethernet_t {
  mac_addr_t dstAddr;
  mac_addr_t srcAddr;
  bit<16> etherType;
}

header arp_t {
  bit<16> htype;
  bit<16> ptype;
  bit<8> hlen;
  bit<8> plen;
  bit<16> operation;
  mac_addr_t sender_hardware_address;
  ipv4_addr_t sender_protocol_address;
  mac_addr_t target_hardware_address;
  ipv4_addr_t target_protocol_address;
}

header ipv4_t {
  // IPv4 header
  bit<4> version;
  bit<4> ihl;
  bit<6> dscp;
  bit<2> ecn;
  bit<16> len;
  bit<16> ident;
  bit<2> flags;
  bit<14> fragment_offset;
  bit<8> time_to_live;
  bit<8> protocol;
  bit<16> checksum;
  ipv4_addr_t source_address;
  ipv4_addr_t target_address;
}

header udp_t {
  bit<16> source_port;
  bit<16> target_port;
  bit<16> len;
  bit<16> checksum;
}

header sml_t {
  worker_id_t rank;
  bit<512> chunk;
}

struct headers {
  ethernet_t eth;
  arp_t arp;
  ipv4_t ipv4;
  udp_t udp;
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
      0x800: parse_ipv4;
      0x806: parse_arp;
      default: accept;
    }
  }

  state parse_arp {
    packet.extract(hdr.arp);
    transition accept;
  }
  
  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      17: parse_udp;
      default: accept;
    }
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition select(hdr.udp.target_port) {
      accumulator_port: parse_sml;
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
    verify_checksum(
      hdr.ipv4.isValid(),
      {
        hdr.ipv4.version,
        hdr.ipv4.ihl,
        hdr.ipv4.dscp,
        hdr.ipv4.ecn,
        hdr.ipv4.len,
        hdr.ipv4.ident,
        hdr.ipv4.flags,
        hdr.ipv4.fragment_offset,
        hdr.ipv4.time_to_live,
        hdr.ipv4.protocol,
        hdr.ipv4.source_address,
        hdr.ipv4.target_address
      },
      hdr.ipv4.checksum,
      HashAlgorithm.csum16
    );
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
  register<bit<512>>(1) accumulated_chunk;
  register<bit<64>>(1) completion_bitmap;

  apply {
    if (hdr.arp.isValid() && hdr.arp.operation == 1 && hdr.arp.target_protocol_address == accumulator_ip) {
      // Our MAC address was requested!
      standard_metadata.egress_spec = standard_metadata.ingress_port; // Reflect packet.
      hdr.arp.operation = 2;
      hdr.arp.target_hardware_address = hdr.arp.sender_hardware_address;
      hdr.arp.target_protocol_address = hdr.arp.sender_protocol_address;
      hdr.arp.sender_hardware_address = accumulator_mac;
      hdr.arp.sender_protocol_address = accumulator_ip;
      hdr.eth.dstAddr = hdr.eth.srcAddr;
      hdr.eth.srcAddr = accumulator_mac;

    } else if (hdr.sml.isValid()) {
      // Handle SML packet

      // Check that address, port, and rank information is valid.
      bool valid_sml_packet = hdr.eth.dstAddr == accumulator_mac;
      valid_sml_packet = valid_sml_packet && hdr.ipv4.target_address == accumulator_ip;
      valid_sml_packet = valid_sml_packet && hdr.udp.source_port == accumulator_port;
      valid_sml_packet = valid_sml_packet && hdr.udp.target_port == accumulator_port;
      valid_sml_packet = valid_sml_packet && hdr.sml.rank != 0xff;
      if (!valid_sml_packet) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Check that this is the first packet from this worker.
      tuple<bool, bool> arrival_result = atomic_enter_bitmap(arrival_bitmap, hdr.sml.rank);
      bool first_arrival = arrival_result[0];
      if (!first_arrival) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Accumulate
      @atomic {
        bit<512> old_value;
        accumulated_chunk.read(old_value, 0);
        bit<512> new_value = old_value + hdr.sml.chunk;
        accumulated_chunk.write(0, new_value);
      }

      // Check whether this chunk is the last chunk to be accumulated.
      tuple<bool, bool> accum_result = atomic_enter_bitmap(completion_bitmap, hdr.sml.rank);
      bool last_accumalation = accum_result[1];
      if (!last_accumalation) {
        mark_to_drop(standard_metadata);
        return;
      }

      // Broadcast result
      hdr.sml.rank = 0xff;
      accumulated_chunk.read(hdr.sml.chunk, 0);
      standard_metadata.mcast_grp = 2;

      // Reset memory.
      // No need to use atomics here since (a) single extern functions are atomic per definition and
      // (b) there is only one thread in this section anyways.
      completion_bitmap.write(0, 0);
      accumulated_chunk.write(0, 0);
      arrival_bitmap.write(0, 0);
    
    } else if (hdr.eth.isValid()) {
      // Normal packet forwarding.
      decide_eth_forward.apply();

    } else {
      mark_to_drop(standard_metadata);

    }
  }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  action write_allreduce_broadcast_headers(mac_addr_t hardware_address, ipv4_addr_t protocol_address) {
    hdr.eth.dstAddr = hardware_address;
    hdr.eth.srcAddr = accumulator_mac;
    hdr.ipv4.source_address = accumulator_ip;
    hdr.ipv4.target_address = protocol_address;
  }

  table allreduce_broadcast {
    key = {
      standard_metadata.egress_rid: exact;
    }
    actions = {
      write_allreduce_broadcast_headers;
      NoAction;
    }
    default_action = NoAction;
  }

  apply {
    if (hdr.sml.isValid() && standard_metadata.mcast_grp == 2) {
      // We are broadcasting an accumulation result. Update all addresses
      allreduce_broadcast.apply();
    }
  }
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    update_checksum(
      hdr.ipv4.isValid(),
      {
        hdr.ipv4.version,
        hdr.ipv4.ihl,
        hdr.ipv4.dscp,
        hdr.ipv4.ecn,
        hdr.ipv4.len,
        hdr.ipv4.ident,
        hdr.ipv4.flags,
        hdr.ipv4.fragment_offset,
        hdr.ipv4.time_to_live,
        hdr.ipv4.protocol,
        hdr.ipv4.source_address,
        hdr.ipv4.target_address
      },
      hdr.ipv4.checksum,
      HashAlgorithm.csum16
    );
    update_checksum(
      hdr.udp.isValid(),
      {
        16w0
      },
      hdr.udp.checksum,
      HashAlgorithm.identity
    );
  }
}

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.eth);
    packet.emit(hdr.arp);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.udp);
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