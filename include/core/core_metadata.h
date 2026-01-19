#ifndef CORE_METADATA_H
#define CORE_METADATA_H

#include <stdint.h>
#include <netinet/in.h>

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

#endif