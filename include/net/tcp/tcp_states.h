#ifndef TCP_STATES_H
#define TCP_STATES_H

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

#endif