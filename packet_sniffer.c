#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp_constants.h"
#include "min_packet_sizes.h"

#define IFACE_LENGTH 64
#define MAX_CAPTURED_BYTES 65535

#define MIN_ETH_HDR_SIZE   14  
#define MIN_ARP_SIZE       28 
#define MIN_ETH_ARP_FRAME  42 

#define MIN_IP4_SIZE       20 
#define MIN_IP6_SIZE       40  
#define MIN_IP6_FRAG_SIZE   8 

#define MIN_TCP_SIZE       20  
#define MIN_UDP_SIZE        8  
#define MIN_ICMP6_SIZE      4  
#define MIN_ICMP_ECHO_SIZE  8  

#define MIN_DNS_HDR_SIZE   12  
#define MIN_DNS_QNAME_MIN   3  
#define MIN_DNS_QTAIL       4  
#define MIN_DNS_QUESTION   (MIN_DNS_QNAME_MIN + MIN_DNS_QTAIL)   
#define MIN_DNS_MSG_SIZE   (MIN_DNS_HDR_SIZE + MIN_DNS_QUESTION) 
#define MIN_DNS_UDP_SIZE   (MIN_UDP_SIZE + MIN_DNS_MSG_SIZE)    

#define MIN_TLS_REC_HDR     5 
#define MIN_TLS_HS_HDR      4  

#define MIN_BOOTP_FIXED    236 
#define MIN_DHCP_COOKIE      4 /
#define MIN_DHCP_BASE      (MIN_BOOTP_FIXED + MIN_DHCP_COOKIE)  

typedef enum {
    TCP_CLOSED_T = 0,
    TCP_LISTEN_T,
    TCP_SYN_RECVD_T,
    TCP_SYN_SENT_T,
    TCP_ESTABLISHED_T,
    TCP_FIN_WAIT_1_T,
    TCP_FIN_WAIT_2_T,
    TCP_CLOSE_WAIT_T,
    TCP_CLOSING_T,
    TCP_TIME_WAIT_T,
    TCP_RST_ACT_T
} tcp_state_t;

typedef enum {
    DHCP_DISCOVER = 1,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_DECLINE,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_RELEASE,
    DHCP_INFORM
} dhcp_message_t;

typedef enum {
    HTTP_GET = 1,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

typedef enum {
    ARP_REQUEST = 1,
    ARP_REPLY = 2
} arp_opcode_t;

typedef enum {
    DNS_NOERROR = 0,
    DNS_FORMERR = 1,
    DNS_SERVFAIL = 2,
    DNS_NXDOMAIN = 3,
    DNS_NOTIMP = 4,
    DNS_REFUSED = 5,
    DNS_YXDOMAIN = 6,
    DNS_YXRRESET = 7,
    DNS_NXRESET = 8,
    DNS_NOTAUTH = 9,
    DNS_NOTZONE = 10
} dns_response_codes_t;

typedef enum {
    DNS_QTYPE_A     = 1,   
    DNS_QTYPE_NS    = 2,  
    DNS_QTYPE_MD    = 3,   
    DNS_QTYPE_MF    = 4,   
    DNS_QTYPE_CNAME = 5,   
    DNS_QTYPE_SOA   = 6,   
    DNS_QTYPE_MB    = 7,  
    DNS_QTYPE_MG    = 8,   
    DNS_QTYPE_MR    = 9,   
    DNS_QTYPE_NULL  = 10,  
    DNS_QTYPE_WKS   = 11,  
    DNS_QTYPE_PTR   = 12,  
    DNS_QTYPE_HINFO = 13, 
    DNS_QTYPE_MINFO = 14,  
    DNS_QTYPE_MX    = 15,  
    DNS_QTYPE_TXT   = 16,  
    DNS_QTYPE_AXFR  = 252, 
    DNS_QTYPE_MAILB = 253, 
    DNS_QTYPE_MAILA = 254, 
    DNS_QTYPE_ANY   = 255 
} dns_qtype_t;

typedef struct{
    uint32_t timestamp;
    uint8_t ip_version;

    union{
        struct{
            struct in_addr src_ip;
            struct in_addr dst_ip;
        }v4;
        struct{
            struct in6_addr src_ip6;
            struct in6_addr dst_ip6;
        }v6;
    }ip;

    uint16_t src_port;
    uint16_t dst_port; 
    uint8_t protocol;

    uint8_t direction;
    uint32_t packet_size;
    uint32_t flow_id;

}core_metadata;

typedef struct{
    core_metadata core;

    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flag;
    uint16_t window_size;
    uint8_t tcp_state;
    uint8_t data_offset;
    uint16_t checksum;

}tcp_metadata_t;

/*typedef struct{

}udp_metadata;

typedef struct{

}ether_metadata;

typedef struct{

}icmp6_metadata;

typedef strcut{

}dns_metadata;

typedef strcut{

}http_metadata;

typedef struct{

}tls_metadata;

typedef struct{

}dhcp_metadata;

typedef strcut{

}arp_metadata;*/



int main(){

    pcap_t *session;
    char interface[IFACE_LENGTH];
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
   

    printf("Enter interface name:\n");
    if(!fgets(interface, IFACE_LENGTH, stdin)){
        fprintf(stderr, "Enter a valid interface name");
        return 1;
    }

    interface[strcspn(interface, "\n")] = '\0';
    printf("Using interface %s\n", interface);


    if(pcap_lookupnet(interface, &net, &mask, errbuff) == -1){
        fprintf(stderr, "Canr get mask for device %s\n", interface);
        net = 0;
        mask = 0;
    }

    session = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuff);

    if(session == NULL){
        fprintf(stderr, "Coldnt open decive %s: %s\n", interface , errbuff);
        return 2;
    }

    //Compatibility check
    if(pcap_datalink(session) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesnt provide ethernet headers, not supported\n", interface);
        return 2;
    }

    // Compile filter expression
    if(pcap_compile(session, &fp,filter_exp, 0, net)==-1){
        fprintf(stderr, "Couldnt parse filter %s:%s\n", filter_exp, pcap_geterr(session));
        return 2;
    }

    //Set compiled filter to session
    if(pcap_setfilter(session, &fp)==-1){
        fprintf(stderr, "Couldnt filter with filter %s:%s\n", filter_exp,pcap_geterr(session));
        return 2;
    }

    packet = pcap_next(session, &header);
    printf("Jacked a packet with length of [%d]:", header.len);
    pcap_freecode(&fp);
    pcap_close(session);
    return 0;
}