/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> operation;
    bit<48> sender_hardware_address;
    bit<32> sender_protocol_address;
    bit<48> target_hardware_address;
    bit<32> target_protocol_address;
}

struct headers {
    ethernet_t ethernet;
    arp_t arp;
}

struct metadata {}

error { UnknownProtocol };

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            0x806: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        log_msg("IPv4");
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        verify(hdr.arp.htype == 1, error.UnknownProtocol);
        verify(hdr.arp.ptype == 0x800, error.UnknownProtocol);
        verify(hdr.arp.hlen == 6, error.UnknownProtocol);
        verify(hdr.arp.plen == 4, error.UnknownProtocol);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Define your own table(s) here

    apply {
        // Apply your own table(s) here
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        // Update checksum
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Define your deparser here
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
