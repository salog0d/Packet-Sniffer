#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include "core/types.h"

typedef struct{
    core_metadata *core;

    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flag;
    uint16_t window_size;
    uint8_t tcp_state;
    uint8_t data_offset;
    uint16_t checksum;

}tcp_metadata_t;

#endif 