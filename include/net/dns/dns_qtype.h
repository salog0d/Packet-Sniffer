#ifndef DNS_QTYPE_H
#define DNS_QTYPE_H

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

#endif