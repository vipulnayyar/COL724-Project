#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


#define SKETCH_NUM_ROWS 3
#define SKETCH_COUNTERS_PER_ROW 16
#define SKETCH_COUNTER_BIT_WIDTH 16
#define SKETCH_COUNTER_MAX_COUNT (1 << SKETCH_COUNTER_BIT_WIDTH) - 1

#define PCM_L0_SIZE 16
#define PCM_L1_SIZE 8
#define PCM_L2_SIZE 4
#define PCM_L3_SIZE 2


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> index_sketch0;
    bit<32> index_sketch1;
    bit<32> index_sketch2;
    
    bit<SKETCH_COUNTER_BIT_WIDTH> value_sketch0;
    bit<SKETCH_COUNTER_BIT_WIDTH> value_sketch1;
    bit<SKETCH_COUNTER_BIT_WIDTH> value_sketch2;

    bit<32> idx0;
    bit<32> idx1;
    bit<32> idx2;
    
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}


parser MyParser(packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            1 : parse_icmp; 
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        packet.emit(hdr.ethernet);
 
        packet.emit(hdr.ipv4);

        packet.emit(hdr.tcp);

        packet.emit(hdr.icmp);
}
}






control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}




control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<SKETCH_COUNTER_BIT_WIDTH>>(SKETCH_COUNTERS_PER_ROW) sketch0;
    register<bit<SKETCH_COUNTER_BIT_WIDTH>>(SKETCH_COUNTERS_PER_ROW) sketch1;
    register<bit<SKETCH_COUNTER_BIT_WIDTH>>(SKETCH_COUNTERS_PER_ROW) sketch2;
    
    // ===== Row 0 =====
    register<bit<16>>(16) pcm_l0_r0;
    register<bit<16>>(8)  pcm_l1_r0;
    register<bit<16>>(4)  pcm_l2_r0;
    register<bit<16>>(2)  pcm_l3_r0;

    // ===== Row 1 =====
    register<bit<16>>(16) pcm_l0_r1;
    register<bit<16>>(8)  pcm_l1_r1;
    register<bit<16>>(4)  pcm_l2_r1;
    register<bit<16>>(2)  pcm_l3_r1;

    // ===== Row 2 =====
    register<bit<16>>(16) pcm_l0_r2;
    register<bit<16>>(8)  pcm_l1_r2;
    register<bit<16>>(4)  pcm_l2_r2;
    register<bit<16>>(2)  pcm_l3_r2;

    action pcm_hash() {
        bit<32> h;

        hash(meta.idx0, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)16);

        hash(meta.idx1, HashAlgorithm.crc32, (bit<32>)1, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)16);

        hash(meta.idx2, HashAlgorithm.crc32, (bit<32>)2, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)16);
    } 

    action pcm_carry_r0(bit<32> idx_l0) {
        // ----- Layer 0 -----
        bit<16> v0;
        pcm_l0_r0.read(v0, idx_l0);

        if (v0 < 15) {
            pcm_l0_r0.write(idx_l0, v0 + 1);
            return;
        }

        // overflow
        pcm_l0_r0.write(idx_l0, 0);
        bit<32> idx_l1 = idx_l0 >> 1;

        // ----- Layer 1 -----
        bit<16> v1;
        pcm_l1_r0.read(v1, idx_l1);

        if (v1 < 15) {
            pcm_l1_r0.write(idx_l1, v1 + 1);
            return;
        }

        pcm_l1_r0.write(idx_l1, 0);
        bit<32> idx_l2 = idx_l1 >> 1;

        // ----- Layer 2 -----
        bit<16> v2;
        pcm_l2_r0.read(v2, idx_l2);

        if (v2 < 15) {
            pcm_l2_r0.write(idx_l2, v2 + 1);
            return;
        }

        pcm_l2_r0.write(idx_l2, 0);
        bit<32> idx_l3 = idx_l2 >> 1;

        // ----- Layer 3 -----
        bit<16> v3;
        pcm_l3_r0.read(v3, idx_l3);

        if (v3 < 15) {
            pcm_l3_r0.write(idx_l3, v3 + 1);
            return;
        }

        // top overflow → saturate
        pcm_l3_r0.write(idx_l3, 15);
        
    }

    action pcm_carry_r1(bit<32> idx_l0) {
        bit<16> v0;
        pcm_l0_r1.read(v0, idx_l0);
    
        if (v0 < 15) {
            pcm_l0_r1.write(idx_l0, v0 + 1);
            return;
        }
    
        pcm_l0_r1.write(idx_l0, 0);
        bit<32> idx_l1 = idx_l0 >> 1;
    
        bit<16> v1;
        pcm_l1_r1.read(v1, idx_l1);
    
        if (v1 < 15) {
            pcm_l1_r1.write(idx_l1, v1 + 1);
            return;
        }
    
        pcm_l1_r1.write(idx_l1, 0);
        bit<32> idx_l2 = idx_l1 >> 1;
    
        bit<16> v2;
        pcm_l2_r1.read(v2, idx_l2);
    
        if (v2 < 15) {
            pcm_l2_r1.write(idx_l2, v2 + 1);
            return;
        }
    
        pcm_l2_r1.write(idx_l2, 0);
        bit<32> idx_l3 = idx_l2 >> 1;
    
        bit<16> v3;
        pcm_l3_r1.read(v3, idx_l3);
    
        if (v3 < 15) {
            pcm_l3_r1.write(idx_l3, v3 + 1);
            return;
        }
    
        pcm_l3_r1.write(idx_l3, 15);
    }

    action pcm_carry_r2(bit<32> idx_l0) {
        bit<16> v0;
        pcm_l0_r2.read(v0, idx_l0);
    
        if (v0 < 15) {
            pcm_l0_r2.write(idx_l0, v0 + 1);
            return;
        }
    
        pcm_l0_r2.write(idx_l0, 0);
        bit<32> idx_l1 = idx_l0 >> 1;
    
        bit<16> v1;
        pcm_l1_r2.read(v1, idx_l1);
    
        if (v1 < 15) {
            pcm_l1_r2.write(idx_l1, v1 + 1);
            return;
        }
    
        pcm_l1_r2.write(idx_l1, 0);
        bit<32> idx_l2 = idx_l1 >> 1;
    
        bit<16> v2;
        pcm_l2_r2.read(v2, idx_l2);
    
        if (v2 < 15) {
            pcm_l2_r2.write(idx_l2, v2 + 1);
            return;
        }
    
        pcm_l2_r2.write(idx_l2, 0);
        bit<32> idx_l3 = idx_l2 >> 1;
    
        bit<16> v3;
        pcm_l3_r2.read(v3, idx_l3);
    
        if (v3 < 15) {
            pcm_l3_r2.write(idx_l3, v3 + 1);
            return;
        }
    
        pcm_l3_r2.write(idx_l3, 15);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    

   action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

    action pcm_insert() {
        pcm_hash();  
    
        pcm_carry_r0(meta.idx0);
        pcm_carry_r1(meta.idx1);
        pcm_carry_r2(meta.idx2);
    }

    apply {

        if (hdr.ipv4.isValid()){
            pcm_insert();
        }

        forwarding.apply();
    }
}


control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}


control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;