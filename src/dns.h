/** 
 * @file dns.h
 *
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty 
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 * Copyright 2022 Stefan Gloor
 *
 * References: RFC1035
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* verbose mode for debugging */
extern uint8_t verbose;

/* flag bits in dns header */
enum dns_qr     { DNS_QR_QUERY, DNS_QR_RESPONSE };
enum dns_opcode { DNS_OPCODE_QUERY, DNS_OPCODE_IQUERY, DNS_OPCODE_STATUS };
enum dns_rcode  { DNS_RCODE_NO_ERR, DNS_RCODE_FORMAT_ERR,
                        DNS_RCODE_SERV_FAIL, DNS_RCODE_NAME_ERR, 
                        DNS_RCODE_NOT_IMPL, DNS_RCODE_REFUSED };
enum dns_type   { DNS_TYPE_A=1, DNS_TYPE_NS, DNS_TYPE_MD, DNS_TYPE_MF,
                        DNS_TYPE_CNAME, DNS_TYPE_SOA, DNS_TYPE_MB,
                        DNS_TYPE_MG, DNS_TYPE_MR, DNS_TYPE_NULL,
                        DNS_TYPE_WKS, DNS_TYPE_PTR, DNS_TYPE_HINFO,
                        DNS_TYPE_MINFO, DNS_TYPE_MX, DNS_TYPE_TXT };

/* TODO: check if union can be used */
struct dns_msg_flags {
        uint8_t qr : 1;
        uint8_t opcode : 4;
        uint8_t aa : 1;
        uint8_t tc : 1;
        uint8_t rd : 1;
        uint8_t ra : 1;
        uint8_t z : 3;
        uint8_t rcode : 4;
};

/* TODO: not needed with union */
#define dns_flags16ptr(x) ((x->qr << 15) | (x->opcode << 11) | (x->aa << 10) | \
                (x->tc << 9) | (x->rd << 8) | (x->ra << 7) | x->rcode)

#define dns_flags16(x) ((x.qr << 15) | (x.opcode << 11) | (x.aa << 10) | \
                (x.tc << 9) | (x.rd << 8) | (x.ra << 7) | x.rcode)


/* header section 4.1.1 (page 26) */
struct dns_header {
        uint16_t transaction_id;        
        struct dns_msg_flags flags; 
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
};

/* question section 4.1.2 (page 28) */
struct dns_question {
        char* qname;
        uint16_t qtype;
        uint16_t qclass;
};

/* resource record (RR) 4.1.3 (page 29) */
struct dns_rr {
        char* name;
        uint16_t type;
        uint16_t _class;
        uint16_t ttl;
        uint16_t rdlength;
        uint8_t* rdata; 
};

/* message format 4.1 (page 25) */
struct dns_msg {
        struct dns_header header;      
        struct dns_question question;
        struct dns_rr answer;
        struct dns_rr authority;
        struct dns_rr additional;
};

/* arguments for thread function */
struct dns_args {
        uint16_t port;
        char* record;
};


/**
 * @brief starts a dns server in a single thread
 * @note does not terminate
 */
void *dns_server(void *args);




