/** 
 * @file dns.c
 * @brief Very minimal DNS server that responds with fixed ip address
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
 */

#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#include "dns.h"

extern volatile sig_atomic_t int_shutdown;

extern char acme_dns_digest[512];

#define write16(dest, src) \
        dest = (src >> 8) & 0xff; *((uint8_t *)&dest + 1) = src & 0xff;

#define read16(dest, src) \
        dest = (src << 8) & 0xff00; dest |= *((uint8_t *)&src + 1) & 0xff 

#ifdef CONFIG_DEBUG_DNS
static void print_flags (struct dns_msg_flags* flags) {
        printf("opcode: %s, ", (flags->qr == DNS_QR_QUERY)?"QUERY":"RESPONSE"); 
        printf("flags: 0x%04x, ", dns_flags16ptr(flags));
        switch(flags->opcode){
                case DNS_OPCODE_QUERY:
                        printf("Standard query, ");
                        break;
                case DNS_OPCODE_IQUERY:
                        printf("Inverse query, ");
                        break;
                case DNS_OPCODE_STATUS:
                        printf("Server status request, ");
                        break;
                default:
                        printf("Warning: OPCODE_RESERVED, ");
        } 
        printf("%s", (flags->aa)?"Authoritative Answer, ":""); 
        printf("%s", (flags->tc)?"Truncation, ":""); 
        printf("%s", (flags->rd)?"Recursion desired, ":""); 
        printf("%s", (flags->ra)?"Recursion available, ":""); 
        switch(flags->rcode){
                case DNS_RCODE_NO_ERR:
                        break;
                case DNS_RCODE_FORMAT_ERR:
                        printf("Format error ");
                        break;
                case DNS_RCODE_SERV_FAIL:
                        printf("Server failure ");
                        break;
                case DNS_RCODE_NAME_ERR:
                        printf("Name error ");
                        break;
                case DNS_RCODE_NOT_IMPL:
                        printf("Not implemented ");
                        break;
                case DNS_RCODE_REFUSED:
                        printf("Refused ");
                        break;
        }
        printf("\n");
}

static void print_msg(struct dns_msg* msg){
        printf(" --- HEADER ---\n");
        printf("id: 0x%04x, ", msg->header.transaction_id);
        print_flags(&msg->header.flags);
        printf("QDCOUNT: 0x%04x, ", msg->header.qdcount);
        printf("ANCOUNT: 0x%04x, ", msg->header.ancount);
        printf("NSCOUNT: 0x%04x, ", msg->header.nscount);
        printf("ARCOUNT: 0x%04x\n ", msg->header.arcount);
        if (msg->header.qdcount > 0){
                printf("--- QUESTION ---\n");
                printf("qname: %s\n",msg->question.qname);
                printf("qtype: 0x%04x\n", msg->question.qtype);
                printf("qclass: 0x%04x\n", msg->question.qclass);
        }
        if (msg->header.ancount > 0){
                printf("--- ANSWER ---\n");
                printf("name: %s\n",msg->answer.name);
                printf("type: 0x%04x\n", msg->answer.type);
                printf("class: 0x%04x\n", msg->answer._class);
                printf("ttl: 0x%04x\n", msg->answer.ttl);
                printf("rdlength: 0x%04x\n", msg->answer.rdlength);
                if (msg->answer.type == DNS_TYPE_A) {
                        printf("rdata: %i.%i.%i.%i\n", msg->answer.rdata[0],
                                msg->answer.rdata[1], msg->answer.rdata[2], 
                                msg->answer.rdata[3]);
                }
                else {
                        printf("rdata: ");
                        for (uint16_t i = 0; i < msg->answer.rdlength; i++) {
                                printf("%c", msg->answer.rdata[i]);
                        } 
                        printf("\n");
                }
        }
        printf("\n");
        /* TODO AUTHORITY and ADDITIONAL */
}
#endif 

static int8_t 
dns_parser(unsigned char* buf, unsigned int len, struct dns_msg* msg) {
        /* 12 byte header */
        read16(msg->header.transaction_id, buf[0]);
       
        /* TODO: probably not needed with union or
         * tidy up with proper macros */
        msg->header.flags.qr = (buf[2] & 0x80) >> 7;
        msg->header.flags.opcode = (buf[2] & 0x78) >> 3;
        msg->header.flags.aa = (buf[2] & 0x04) >> 2;
        msg->header.flags.tc = (buf[2] & 0x02) >> 1;
        msg->header.flags.rd = (buf[2] & 0x01);
        msg->header.flags.ra = (buf[3] & 0x80) >> 7;
        msg->header.flags.z = (buf[3] & 0x70) >> 4;
        msg->header.flags.rcode = (buf[3] & 0x0f);

        read16(msg->header.qdcount, buf[4]);
        read16(msg->header.ancount, buf[6]);
        read16(msg->header.nscount, buf[8]);
        read16(msg->header.arcount, buf[10]);
       
        /* Question section */
        if (msg->header.qdcount == 0) {
                printf("Question section is empty!\n");
                return -1;
        }
        if (msg->header.qdcount > 1) {
                printf("Not implemented: question section contains"
                                "more than one entry!\n");
                return -1;
        }
        /* QNAME */
        unsigned int i = 12;
        msg->question.qname = (char*)&buf[12];
        while (buf[i] != 0 && i < len) { i++; }
        if (i == len){
                return -1;
        }
        *(msg->question.qname + i) = '\0';
       
        /* QTYPE */
        read16(msg->question.qtype, buf[i+1]);
        
        /* QCLASS */
        read16(msg->question.qclass, buf[i+3]);
      
        /* ANSWER SECTION */
        if (msg->header.ancount > 0){
                printf("Not implemented: query contains answer!\n");
                return -1;
        }

        /* TODO parse authority and additional section */
        
#ifdef CONFIG_DEBUG_DNS
        if (verbose) {
                printf("DNS message parsing successful.\n");
                print_msg(msg);
        }
#endif
        return 0;
}

uint8_t dns_populate(unsigned char* buf, int len, struct dns_msg* msg){   
        const uint8_t header_offset = 12;
        assert(len > 0);
        assert(buf != NULL);
        assert(msg != NULL);

        /* 12 byte header */
        write16(buf[0], msg->header.transaction_id);
        write16(buf[2], dns_flags16(msg->header.flags));
        write16(buf[4], msg->header.qdcount);
        write16(buf[6], msg->header.ancount);
        write16(buf[8], msg->header.nscount);
        write16(buf[10], msg->header.arcount);

        assert(msg->header.ancount == 1);
        assert(msg->header.flags.qr == DNS_QR_RESPONSE);

        /* populating question section */
        uint16_t q_offset = strlen(msg->question.qname);
        
        memcpy(buf+header_offset, msg->question.qname, 
                        q_offset);
       
        buf[header_offset+q_offset++] = '\0';
        
        buf[header_offset+q_offset++] 
                = (msg->question.qtype & 0xff00) >> 8;
        buf[header_offset+q_offset++] = (msg->question.qtype & 0x00ff);
        
        buf[header_offset+q_offset++] 
                = (msg->question.qclass & 0xff00) >> 8;
        buf[header_offset+q_offset++] = (msg->question.qclass & 0x00ff);
     
        /* parse name field */
        uint16_t name_tot_len = 0; //total length including length octets
        while (msg->answer.name[name_tot_len] != '\0'){
                uint16_t name_len = msg->answer.name[name_tot_len];
                name_tot_len += name_len + 1;
        }
        memcpy(buf+header_offset+q_offset, msg->answer.name, name_tot_len);
        buf[header_offset+q_offset+name_tot_len] = '\0';
       
        /* populating rest of the fields */
        /* TODO: use 16 bit macro */
        uint16_t i = name_tot_len + 1;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = msg->answer.type;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = msg->answer._class;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = msg->answer.ttl;
        buf[header_offset+q_offset+i++] = 0x00;
        buf[header_offset+q_offset+i++] = msg->answer.rdlength;
       
        /* copy RDATA */
        memcpy(&buf[i+header_offset+q_offset], 
                        msg->answer.rdata, msg->answer.rdlength);
       
        /* return total length */
        return i+header_offset+q_offset+msg->answer.rdlength;
}

static int8_t dns(uint16_t port, const char* record){
        /* open udp socket */
        struct sockaddr_in si_me; 
        struct sockaddr_in si_other;

        int udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(port);
        si_me.sin_addr.s_addr = inet_addr(record);

        unsigned char buf[2048] = {0};
        if (bind(udp_socket, (struct sockaddr*)&si_me, sizeof(si_me))) {
                printf("Error: DNS server bind failed.\n");
                exit(-1);
                return -1;
        }
        socklen_t addr_len = sizeof(si_other);

        while(!int_shutdown) {
                /* blocking call waits for udp packet */
                int len = recvfrom(udp_socket, buf, 2048, MSG_DONTWAIT,
                                (struct sockaddr*)&si_other, &addr_len);
                if (len > 0) {
#ifdef CONFIG_DEBUG_DNS
                        if (verbose) {
                                printf("Received UDP packet with %d bytes\n", len);
                        }
#endif
                        struct dns_msg rx_msg;
                        if (dns_parser(buf, len, &rx_msg)){
                                printf("DNS message parsing failed.\n");
                        }
                        else {
#ifdef CONFIG_DEBUG_DNS
                                if (verbose) { 
                                        printf("Sending ANSWER\n");
                                }
#endif
                                /* building answer message */
                                struct dns_msg tx_msg;
                                tx_msg.header.transaction_id 
                                        = rx_msg.header.transaction_id;
                                
                                tx_msg.header.flags.opcode = DNS_OPCODE_QUERY;
                                tx_msg.header.flags.qr = DNS_QR_RESPONSE;
                                tx_msg.header.flags.aa = 1;
                                tx_msg.header.flags.rd = rx_msg.header.flags.rd;
                                tx_msg.header.flags.ra = 1;
                                tx_msg.header.flags.z = 0;
                                tx_msg.header.flags.rcode = DNS_RCODE_NO_ERR;

                                tx_msg.header.qdcount = 1;
                                tx_msg.header.ancount = 1;
                                tx_msg.header.nscount = 0;
                                tx_msg.header.arcount = 0;
                                
                                tx_msg.question.qname = rx_msg.question.qname;
                                tx_msg.question.qclass = 1;
                                tx_msg.question.qtype = rx_msg.question.qtype;
                
                                tx_msg.answer.name = rx_msg.question.qname;
                                
                                tx_msg.answer.rdata = NULL;
                                tx_msg.answer.rdlength = 0;
                                if (rx_msg.question.qtype == DNS_TYPE_A) {
                                        char ip[4];
                                        if (sscanf(record, "%hhi.%hhi.%hhi.%hhi", 
                                                                ip, ip+1, ip+2, ip+3) < 4) {
                                                printf("malformed IPv4 address!\n");
                                                exit(-1);
                                        }
                                        tx_msg.answer.rdata = (uint8_t*)ip;
                                        tx_msg.answer.rdlength = 4;
                                        tx_msg.answer.ttl = 4096;
                                        tx_msg.answer.type = rx_msg.question.qtype;
                                        tx_msg.answer._class = 1;
                                }
                                if (rx_msg.question.qtype == DNS_TYPE_TXT) {
                                        char* data = calloc(256, sizeof(char));
                                        char* digest = calloc(128, sizeof(char));
                                        //char* token = acme_get_token_dns();
                                        printf("Reading token from %p\n", acme_dns_digest);
                                        strcpy(digest,acme_dns_digest); 
                                        printf("Digest: %s\n", digest);
                                        strcpy(data+1, digest);
                                        *data = (char)strlen(data+1);
                                        tx_msg.answer.rdata = (uint8_t*)data;
                                        tx_msg.answer.rdlength = strlen(data);
                                        tx_msg.answer.ttl = 4096;
                                        tx_msg.answer.type = rx_msg.question.qtype;
                                        tx_msg.answer._class = 1;
                                }

                                len = dns_populate(buf, len, &tx_msg);
#ifdef CONFIG_DEBUG_DNS
                                if (verbose) {
                                        print_msg(&tx_msg);
                                }
#endif
                                sendto(udp_socket, buf, len, 0,
                                                (struct sockaddr*)&si_other, addr_len); 
                        }
                }
        }
        close(udp_socket);
        printf("Terminated DNS server.\n");
        return 0;
}

void* dns_server(void* args){
        struct dns_args* server_args = (struct dns_args*) args; 
        dns(server_args->port, server_args->record);
        return NULL;
}


