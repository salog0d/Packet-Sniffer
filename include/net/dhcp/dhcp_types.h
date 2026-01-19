#ifndef DHCP_TYPES_H
#define DHCP_TYPES_H

typedef enum {
    DHCP_MSG_DISCOVER = 1,
    DHCP_MSG_OFFER,
    DHCP_MSG_REQUEST,
    DHCP_MSG_DECLINE,
    DHCP_MSG_ACK,
    DHCP_MSG_NAK,
    DHCP_MSG_RELEASE,
    DHCP_MSG_INFORM
} dhcp_msg_type_t;

#endif
