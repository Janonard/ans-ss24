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

    // TODO: UDP checksum
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

    } else {
      mark_to_drop(standard_metadata);
      
    }
  }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  apply {
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
    update_checksum( // TODO: Compute actual checksum
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