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
typedef bit<8> rank_t; /*< Worker IDs */
typedef bit<8> chunk_id_t;

#define PKT_INSTANCE_TYPE_REPLICATION 5

const rank_t n_workers = 8;
const mac_addr_t accumulator_mac = 0x080000000101; // 08:00:00:00:01:01
const ipv4_addr_t accumulator_ip = 0x0a000101; // 10.0.1.1
const bit<16> accumulator_port = 0x4200;

const int n_slot_bits = 1;
const int n_slots = 1 << n_slot_bits;
typedef bit<1> slot_id_t; 

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

header sml_header_t {
  rank_t rank;
  chunk_id_t chunk_id;
  chunk_id_t ack_chunk_id;
}

header sml_body_t {
  bit<2048> chunk;
}

struct headers {
  ethernet_t eth;
  arp_t arp;
  ipv4_t ipv4;
  udp_t udp;
  sml_header_t sml_header;
  sml_body_t sml_body;
}

struct metadata {}

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
      accumulator_port: parse_sml_header;
      default: accept;
    }
  }

  state parse_sml_header {
    packet.extract(hdr.sml_header);
    transition select(hdr.sml_header.chunk_id) {
      0xff: accept;
      default: parse_sml_body;
    }
  }

  state parse_sml_body {
    packet.extract(hdr.sml_body);
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
    verify_checksum_with_payload(
      hdr.udp.isValid(),
      {
        hdr.ipv4.source_address,
        hdr.ipv4.target_address,
        8w0,
        hdr.ipv4.protocol,
        hdr.udp.len,
        hdr.udp.source_port,
        hdr.udp.target_port,
        hdr.udp.len,
        hdr.sml_header,
        hdr.sml_body
      },
      hdr.udp.checksum,
      HashAlgorithm.csum16
    );
  }
}

/*
 * Gate-Related Functions
 */

tuple<bool, bool> enter_gate(register<bit<64>> gate, in slot_id_t slot_id, in rank_t rank) {
  bit<64> old_gate_value;
  bit<64> new_gate_value;
  @atomic {
    gate.read(old_gate_value, (bit<32>) slot_id);

    new_gate_value = old_gate_value | (64w1 << rank);

    gate.write((bit<32>) slot_id, new_gate_value);
  };
  bool valid_entry = (old_gate_value & (64w1 << rank)) == 0;
  bool last_entry = new_gate_value == ((64w1 << n_workers) - 1); 
  return { valid_entry, last_entry };
}

void enter_and_reset_gate(register<bit<64>> gate, in slot_id_t slot_id, in rank_t rank) {
  gate.write((bit<32>) slot_id, 64w1 << rank);
}

/*
 * Lock-Related Functions
 */

bool acquire_lock(register<bit<1>> lock_register, in slot_id_t slot_id) {
  bit<1> is_already_blocked;
  @atomic {
    lock_register.read(is_already_blocked, (bit<32>) slot_id);
    lock_register.write((bit<32>) slot_id, 1);
  }
  return is_already_blocked == 0;
}

void release_lock(register<bit<1>> lock_register, in slot_id_t slot_id) {
  lock_register.write((bit<32>) slot_id, 0);
}

/*
 * Chunk-Related Functions
 */

bit<2048> accumulate_chunk(register<bit<2048>> chunk_register, in slot_id_t slot_id, in bit<2048> chunk) {
  bit<2048> old_chunk_value;
  bit<2048> new_chunk_value;
  @atomic {
    chunk_register.read(old_chunk_value, (bit<32>) slot_id);
    new_chunk_value = old_chunk_value + chunk;
    chunk_register.write((bit<32>) slot_id, new_chunk_value);
  }
  return new_chunk_value;
}

bit<2048> read_chunk(register<bit<2048>> chunk_register, in slot_id_t slot_id) {
  bit<2048> chunk_value;
  chunk_register.read(chunk_value, (bit<32>) slot_id);
  return chunk_value;
}

/*
 * Misc. Function
 */

slot_id_t chunk_to_slot(in chunk_id_t chunk_id) {
  return chunk_id[n_slot_bits-1:0];
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

  register<bit<1>>(n_slots) slot_lock;

  register<bit<64>>(n_slots) completion_gate;
  register<bit<64>>(n_slots) acknowledgement_gate;
  register<bit<2048>>(n_slots) chunk;
  register<bit<8>>(n_slots) chunk_id;

  apply {
    if (standard_metadata.checksum_error == 1) {
      // Drop if checksum invalid.
      mark_to_drop(standard_metadata);

    } else if (hdr.arp.isValid() && hdr.arp.operation == 1 && hdr.arp.target_protocol_address == accumulator_ip) {
      // Our MAC address was requested!
      standard_metadata.egress_spec = standard_metadata.ingress_port; // Reflect packet.
      hdr.arp.operation = 2;
      hdr.arp.target_hardware_address = hdr.arp.sender_hardware_address;
      hdr.arp.target_protocol_address = hdr.arp.sender_protocol_address;
      hdr.arp.sender_hardware_address = accumulator_mac;
      hdr.arp.sender_protocol_address = accumulator_ip;
      hdr.eth.dstAddr = hdr.eth.srcAddr;
      hdr.eth.srcAddr = accumulator_mac;

    } else if (hdr.sml_header.isValid()) {
      // Handle SML packet

      // Check that address, port, and rank information is valid.
      bool valid_sml_packet = hdr.eth.dstAddr == accumulator_mac;
      valid_sml_packet = valid_sml_packet && hdr.ipv4.target_address == accumulator_ip;
      valid_sml_packet = valid_sml_packet && hdr.udp.source_port == accumulator_port;
      valid_sml_packet = valid_sml_packet && hdr.udp.target_port == accumulator_port;
      valid_sml_packet = valid_sml_packet && hdr.sml_header.rank != 0xff;
      valid_sml_packet = valid_sml_packet && (hdr.sml_header.chunk_id == 0xff || hdr.sml_body.isValid());
      valid_sml_packet = valid_sml_packet && !(hdr.sml_header.chunk_id == 0xff && hdr.sml_body.isValid());
      if (!valid_sml_packet) {
        mark_to_drop(standard_metadata);
        return;
      }

      rank_t rank = hdr.sml_header.rank;

      // Packet acknowledgement
      if (hdr.sml_header.ack_chunk_id != 0xff) {
        slot_id_t slot_id = chunk_to_slot(hdr.sml_header.ack_chunk_id);

        if (!acquire_lock(slot_lock, slot_id)) {
          // Slot is already locked. Try again later.
          log_msg("SML: Can't aquire slot {}'s lock for rank {} for ack processing", {slot_id, rank});
          mark_to_drop(standard_metadata);
          return;
        }

        chunk_id_t slot_chunk_id;
        chunk_id.read(slot_chunk_id, (bit<32>) slot_id);

        if (slot_chunk_id != hdr.sml_header.ack_chunk_id) {
          // They are trying to acknowledge a chunk that's not here.
          // Something's wrong. Drop this packet and abord.
          mark_to_drop(standard_metadata);
          release_lock(slot_lock, slot_id);
          return;
        }

        tuple<bool, bool> entrance_result = enter_gate(acknowledgement_gate, slot_id, rank);
        bool ack_complete = entrance_result[1];

        log_msg("SML: Ack for chunk {} from rank {}", {hdr.sml_header.ack_chunk_id, rank});
        if (ack_complete) {
          completion_gate.write((bit<32>) slot_id, 0);
          acknowledgement_gate.write((bit<32>) slot_id, 0);
          chunk.write((bit<32>) slot_id, 0);
          chunk_id.write((bit<32>) slot_id, 0);
          log_msg("SML: Resetting Slot {}", {slot_id});
        }

        release_lock(slot_lock, slot_id);
      }

      // Accumulation
      if (hdr.sml_header.chunk_id != 0xff) {
        slot_id_t slot_id = chunk_to_slot(hdr.sml_header.chunk_id);

        if (!acquire_lock(slot_lock, slot_id)) {
          // Slot is already locked. Try again later.
          log_msg("SML: Can't aquire slot {}'s lock for rank {} for accumulation", {slot_id, rank});
          mark_to_drop(standard_metadata);
          return;
        }

        chunk_id_t old_chunk_id;
        chunk_id.read(old_chunk_id, (bit<32>) slot_id);

        if (old_chunk_id == hdr.sml_header.chunk_id) {
          tuple<bool, bool> entrance_result = enter_gate(completion_gate, slot_id, rank);
          bool first_packet_from_rank = entrance_result[0];
          bool reduce_complete = entrance_result[1];

          bit<2048> chunk_value;
          if (first_packet_from_rank) {
            log_msg("SML: Accumulating onto chunk {} from rank {}", {hdr.sml_header.chunk_id, rank});
            chunk_value = accumulate_chunk(chunk, slot_id, hdr.sml_body.chunk);
          } else {
            log_msg("SML: Reading chunk {} for rank {}", {hdr.sml_header.chunk_id, rank});
            chunk_value = read_chunk(chunk, slot_id);
          }

          if (reduce_complete && first_packet_from_rank) {
            // This is the last packet to arrive for this chunk, broadcast the result
            hdr.sml_header.rank = 0xff;
            hdr.sml_header.ack_chunk_id = 0xff;
            hdr.sml_body.chunk = chunk_value;
            standard_metadata.mcast_grp = 2;
            log_msg("SML: Broadcasting chunk {}", {hdr.sml_header.chunk_id});
          } else if (reduce_complete && !first_packet_from_rank) {
            // The worker has resent the packet and the the computation is complete.
            // Resend the result
            hdr.sml_header.rank = 0xff;
            hdr.sml_header.ack_chunk_id = 0xff;
            hdr.sml_body.chunk = chunk_value;

            ipv4_addr_t swap_ip = hdr.ipv4.source_address;
            hdr.ipv4.source_address = hdr.ipv4.target_address;
            hdr.ipv4.target_address = swap_ip;

            mac_addr_t swap_mac = hdr.eth.srcAddr;
            hdr.eth.srcAddr = hdr.eth.dstAddr;
            hdr.eth.dstAddr = swap_mac;

            standard_metadata.egress_spec = standard_metadata.ingress_port;
            log_msg("SML: Resending chunk {} to rank {}", {hdr.sml_header.chunk_id, rank});
          } else {
            // The computation is not complete, we can't resend the result yet.
            mark_to_drop(standard_metadata);
          }

        } else if (old_chunk_id == 0) {
          // (Re-)initialize the registers
          enter_and_reset_gate(completion_gate, slot_id, rank);
          chunk.write((bit<32>) slot_id, hdr.sml_body.chunk);
          chunk_id.write((bit<32>) slot_id, hdr.sml_header.chunk_id);
          mark_to_drop(standard_metadata);
          log_msg("SML: Initializing slot for chunk {} from rank {}", {hdr.sml_header.chunk_id, rank});
        }

        release_lock(slot_lock, slot_id);
      } else {
        mark_to_drop(standard_metadata);
      }

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
    if (hdr.sml_header.isValid() && standard_metadata.mcast_grp == 2) {
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
    update_checksum_with_payload(
      hdr.udp.isValid(),
      {
        hdr.ipv4.source_address,
        hdr.ipv4.target_address,
        8w0,
        hdr.ipv4.protocol,
        hdr.udp.len,
        hdr.udp.source_port,
        hdr.udp.target_port,
        hdr.udp.len,
        hdr.sml_header,
        hdr.sml_body
      },
      hdr.udp.checksum,
      HashAlgorithm.csum16
    );
  }
}

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.eth);
    packet.emit(hdr.arp);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.udp);
    packet.emit(hdr.sml_header);
    packet.emit(hdr.sml_body);
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