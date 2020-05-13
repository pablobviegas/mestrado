#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthAddr_t; 
typedef bit<32> IPv4Addr_t;
typedef bit<16> TCPAddr_t;

const bit<32> TYPE_IPV4 = 0x0800;
//const bit<32> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_TCP = 6;


//Standard Ethernet Header
header ethernet_t {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<32> etherType;
}

//IPv4 header without options
header ipv4_t {
       bit<4> version;
       bit<4> ihl;
       bit<8> tos;
       bit<16> totalLen;
       bit<16> identification;
       bit<3> flags;
       bit<13> fragOffset;
       bit<8> ttl;
       bit<16> protocol;
       bit<16> hdrChecksum;
       IPv4Addr_t srcAddr;
       IPv4Addr_t dstAddr;
}

/*
//IPv6 header
header ipv6_t {
       bit<4> version;
       bit<8> trafficClass;
       bit<20> flowLabel;
       bit<16> payloadLen;
       bit<16> nxt;
       bit<8> hopLimit;
       bit<128> srcAddr;
       bit<128> dstAddr;
}

*/

//TCP header without options
header tcp_t {
       bit<16> srcPort;
       bit<16> dstPort;
       bit<32> seqNo;
       bit<32> ackNo;
       bit<4> dataOffset;
       bit<4> res;
       bit<8> flags;
       bit<16> window;
       bit<16> checksum;
       bit<16> urgentPtr;
}


// List of all recognized headers
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    //ipv6_t ipv6;
    tcp_t tcp;
}


// user defined metadata
// used for coding the decision 
struct metadata {
    bit<7> dist0;
    bit<7> dist1;
    bit<7> dist2;
    bit<7> dist3;
    bit<7> dist4;
}

/* PARSER */


//@Xilinx_MaxPacketRegion(8192)
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            //TYPE_IPV6 : parse_ipv6;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP : parse_tcp;
            default : accept;
        }
    }

    /*
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nxt) {
            TYPE_TCP : parse_tcp;
            default : accept;
        }
    }
    
    */

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
}

/* CHECKSUM VERIFICATION */ 
control MyVerifyChecksum(inout headers hdr, 
                         inout metadata meta){
    apply{  }
}

/* INGRESS PROCESSING */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action set_dist0(bit<7> code){
        meta.dist0 = code;
    }
    
    action set_dist1(bit<7> code){
        meta.dist1 = code;
    }
    action set_dist2(bit<7> code){
        meta.dist2 = code;
    }
    action set_dist3(bit<7> code){
        meta.dist3 = code;
    }
    action set_dist4(bit<7> code){
        meta.dist4 = code;
    }



// Calculate distance vector 0
    table tdist0{
        key = {  standard_metadata.pkt_len++hdr.ipv4.protocol++hdr.ipv4.flags++hdr.tcp.srcPort++hdr.tcp.dstPort:ternary @name("features"); }

         actions = {
            set_dist0;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

// Calculate distance vector 1
    table tdist1{
        key = {  standard_metadata.pkt_len++hdr.ipv4.protocol++hdr.ipv4.flags++hdr.tcp.srcPort++hdr.tcp.dstPort:ternary @name("features"); }

         actions = {
            set_dist1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

// Calculate distance vector 2
  table tdist2 {
         key = {  standard_metadata.pkt_len++hdr.ipv4.protocol++hdr.ipv4.flags++hdr.tcp.srcPort++hdr.tcp.dstPort:ternary @name("features"); }
        
         actions = {
            set_dist2;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

// Calculate distance vector 3
  table tdist3 {

         key = {  standard_metadata.pkt_len++hdr.ipv4.protocol++hdr.ipv4.flags++hdr.tcp.srcPort++hdr.tcp.dstPort:ternary @name("features"); }

         actions = {
            set_dist3;
            NoAction;
        }
        size =64;
        default_action = NoAction;
    }

// Calculate distance vector 4
  table tdist4{
         key = {  standard_metadata.pkt_len++hdr.ipv4.protocol++hdr.ipv4.flags++hdr.tcp.srcPort++hdr.tcp.dstPort:ternary @name("features"); }

         actions = {
            set_dist4;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


    apply {

        meta.dist0=0;
        meta.dist1=0;
        meta.dist2=0;
        meta.dist3=0;
        meta.dist4=0;
       
        tdist0.apply();
        tdist1.apply(); 
        tdist2.apply();
        tdist3.apply();
        tdist4.apply();

//Select the destination port based on the classification - shortest distance

        if ((meta.dist0<meta.dist1) && (meta.dist0<meta.dist2) && (meta.dist0<meta.dist3) && (meta.dist0<meta.dist4)) {
            standard_metadata.dst_port = 8w0b00000001;
        }
        else{
          if ((meta.dist1<=meta.dist0) && (meta.dist1<meta.dist2) && (meta.dist1<meta.dist3) && (meta.dist1<meta.dist4)) {
              standard_metadata.dst_port = 8w0b00000100;
          }
          else{
            if ((meta.dist2<=meta.dist0) && (meta.dist2<=meta.dist1) && (meta.dist2<meta.dist3) && (meta.dist2<meta.dist4)) {
                standard_metadata.dst_port = 8w0b00010000;
            }
            else{
              if ((meta.dist3<=meta.dist0) && (meta.dist3<=meta.dist1) && (meta.dist3<=meta.dist2) && (meta.dist3<meta.dist4)) {
                  standard_metadata.dst_port = 8w0b01000000;
              }
              else
              {
                    standard_metadata.dst_port = 8w0b00000010; //send to host
              }  
            } 
            } 
         }
      }
}

/* EGRESS PROCESSING */
control MyEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    apply {  }
}

/* CHECKSUM UPDATE */
control MyComputeChecksum (inout headers hdr,
                           inout metadata meta) {
    apply {
    update_checksum(
    hdr.ipv4.isValid(),
        {   hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.tos,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        
    /*
    update_checksum(
    hdr.ipv6.isValid(),
        {   hdr.ipv6.version,
            hdr.ipv6.trafficClass,
            hdr.ipv6.flowLabel,
            hdr.ipv6.nxt,
            hdr.ipv6.hopLimit,
            hdr.ipv6.srcAddr,
            hdr.ipv6.dstAddr },
            HashAlgorithm.csum16);

    */

    update_checksum(
    hdr.tcp.isValid(),
        {   hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seqNo,
            hdr.tcp.ackNo,
            hdr.tcp.dataOffset,
            hdr.tcp.res,
            hdr.tcp.flags,
            hdr.tcp.window,
            hdr.tcp.urgentPtr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
   
    }
}
/* DEPARSER */

//@Xilinx_MaxPacketRegion(1024)
control MyDeparser(packet_out packet,
                    in headers hdr ) { //,
                    //inout metadata meta,
                    //inout standard_metadata_t standard_metadata) { 
    apply {
       packet.emit(hdr.ethernet); 
       packet.emit(hdr.ipv4);
       //packet.emit(hdr.ipv6);
	   packet.emit(hdr.tcp);
    }
}


/* SWITCH */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;