/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> operation;
    macAddr_t sender_hardware_address;
    ip4Addr_t sender_protocol_address;
    macAddr_t target_hardware_address;
    ip4Addr_t target_protocol_address;
}

header ipv4_t {
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
    ip4Addr_t source_address;
    ip4Addr_t target_address;
}

struct headers {
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
}

struct metadata {
    
}

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
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4, error.UnknownProtocol);
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


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action respond_arp_request(macAddr_t router_mac, ip4Addr_t router_ip) {
        hdr.arp.target_hardware_address = hdr.arp.sender_hardware_address;
        hdr.arp.target_protocol_address = hdr.arp.sender_protocol_address;
        hdr.arp.sender_hardware_address = router_mac;
        hdr.arp.sender_protocol_address = router_ip;
        hdr.arp.operation = 2; // RESPONSE
        
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table handle_arp {
        key = {
            hdr.arp.target_protocol_address: exact;
            hdr.arp.operation: exact;
        }
        actions = {
            respond_arp_request;
            drop;
        }
        default_action = drop();
    }


    action forward_ip_packet(bit<9> out_port, macAddr_t src_mac, macAddr_t dst_mac) {
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;
        hdr.ipv4.time_to_live = hdr.ipv4.time_to_live - 1;
        standard_metadata.egress_spec = out_port;
    }

    table handle_ipv4 {
        key = {
            hdr.ipv4.target_address: lpm;
        }
        actions = {
            forward_ip_packet;
            drop;
        }
        default_action = drop();
    }

    action start_intercept() {
        log_msg("wuhuuu");
    }

    action nop() {

    }

    table decide_intercept {
        key = {
            hdr.ipv4.source_address: exact;
            hdr.ipv4.target_address: exact;
        }
        actions = {
            start_intercept;
            nop;
        }
        default_action = nop();
    }

    apply {
        if (hdr.arp.isValid()) {
            handle_arp.apply();
        } else if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.time_to_live > 1) {
                decide_intercept.apply();
                handle_ipv4.apply();
            } else {
                drop();
            }
        }
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
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
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
