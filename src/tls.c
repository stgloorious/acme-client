/** 
 * @file tls.c
 * @brief Very minimal HTTPS/TLS server
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>


#include "tls.h"

extern volatile sig_atomic_t int_shutdown;

void* https_cert_server(void* port){
        struct https_args args
                = *((struct https_args*)port);
        https_start(args.port, args.host, "example.com");
        return NULL;
}

SSL_CTX* tls_create_context() {
       const SSL_METHOD* method;
       SSL_CTX* ctx;
       method = TLS_server_method();
        ctx = SSL_CTX_new(method);
        if (!ctx){
                printf("SSL context creation failed.\n");
        }
        return ctx;
}

int password_cb(char* buf, int size, int rwflag, void* u){
        strcpy(buf,"password");
        return strlen(buf);
}

uint8_t tls_conf_context(SSL_CTX *ctx) {
        SSL_CTX_set_default_passwd_cb(ctx, password_cb);
        if (SSL_CTX_use_certificate_chain_file
                (ctx, "cert.crt") <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file
                        (ctx, "client.key", SSL_FILETYPE_PEM) <= 0 ) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
        return 0;
}
       
uint8_t https_start(int16_t port, char* record, char* host){
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(record);

        int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, 
                        &(int){1}, sizeof(int));
        setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEPORT, 
                        &(int){1}, sizeof(int));
        
        int flags = fcntl(tcp_socket, F_GETFL);
        flags |= O_NONBLOCK;
        fcntl(tcp_socket,F_SETFL, flags);

        if (bind(tcp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0){
                printf("Error: HTTPS certificate server bind failed.\n");
                exit(-1);
        }
        listen(tcp_socket, 10);


        SSL_CTX* ctx = tls_create_context();
        tls_conf_context(ctx);

        unsigned int len = sizeof(addr);
        SSL *ssl;
        char reply[512] = "HTTP/1.1 200 OK\r\nContent-Length: "
                "0\r\nConnection: keep-alive\r\nHost: ";
        strcpy(reply+strlen(reply), host);
        strcpy(reply+strlen(reply), "\r\n\r\n");
        
        int client = -1;
        while(!int_shutdown) { 
                while(!int_shutdown && client == -1) {
                        client = accept(tcp_socket, 
                                        (struct sockaddr*)&addr, &len);
                }
                printf("Accepted new TLS connection\n");
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client);

                if (SSL_accept(ssl) > 0){
                        char buf[2048];
                        int len = SSL_read(ssl,buf,sizeof(buf)-1);
                        if (len > 0) {
                                buf[len-1]='\0';
                                printf("Received %i bytes over TLS:\n%s\n",len, buf);
                                printf("Replying with %s\n", reply);
                                SSL_write(ssl, reply, strlen(reply));
                                printf("Reply sent.\n");
                        }
                        else {
                                printf("Error: received empty message!\n");
                        }
                }
                else {
                        ERR_print_errors_fp(stderr);
                }
                printf("Shutting down SSL context.\n");
                //SSL_shutdown(ssl);
                printf("Releasing SSL context.\n");
                //SSL_free(ssl);
                printf("Closing TLS connection.\n");
                close(client);
                client = -1;
                printf("Closed TLS connection.\n");
        }
        printf("Shutting down HTTPS certificate server.\n");
        close(tcp_socket);
        SSL_CTX_free(ctx);
        printf("Terminated HTTPS certificate server\n");
        return 0;
}

