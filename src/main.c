/** 
 * @file main.c
 * @brief ACME client project for network security lecture 263-4640-00
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

#include <argp.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <signal.h>
#include <stdbool.h>
#include <cjson/cJSON.h>


#include "string.h"
#include "args.h"
#include "dns.h"
#include "http.h"
#include "acme.h"
#include "b64.h"
#include "crypt.h"
#include "tls.h"

uint8_t verbose = 0;

volatile sig_atomic_t int_shutdown = 0;

static void int_handler(int dummy) {
        int_shutdown = 1; 
}

int main (int argc, char** argv) {
        signal(SIGINT, int_handler);
        struct arguments arguments;

        arguments.dir_url = "";
        arguments.record = "";
        arguments.domain_list = NULL;
        arguments.ndomain = 0;
        arguments.revoke = 0;
        arguments.verbose = 0;

        argp_parse(&argp, argc, argv, 0, 0, &arguments);
        verbose = arguments.verbose;
        if (verbose) {
#ifdef CONFIG_PRINT_ARGS
                printf("Given command line options:\n");
                printf("CHALLENGE_TYPE = %s\n", arguments.challenge_type);
                printf("ndomain = %i\n", arguments.ndomain);
                for (int i = 0; i < arguments.ndomain; i++){
                        char buf[256];
                        string_list_pop_back(arguments.domain_list, buf);
                        printf("DOMAIN = %s\n", buf);
                }
                printf("DIR_URL = %s\n", arguments.dir_url);
                printf("record = %s\n", arguments.record);
                printf("revoke = %i\n", arguments.revoke);
                printf("verbose = %i\n\n", arguments.verbose);
#endif
        }
#ifdef CONFIG_LOG_FILE
        FILE *logf;
        if ((logf=freopen("log.txt", "w", stdout)) == NULL) {
                printf("Cannot open log file.\n");
                return -1;
        }
#endif
        printf("Using OpenSSL version: %s\n", OPENSSL_VERSION_TEXT); 
      
        EVP_PKEY *key = NULL;
        crypt_new_key(&key);

        
        pthread_t dns_thr;
        pthread_t http_shutdown_thr;
        pthread_t http_chal_thr;
        pthread_t https_cert_thr;
        void* dns_thr_result;
        void* http_shutdown_thr_result;
        void* http_chal_thr_result;
        void* https_cert_thr_result;
 
        struct dns_args dargs = { 10053, arguments.record };
        pthread_create(&dns_thr, NULL, dns_server, &dargs);
        printf("DNS server started on port %i\n", dargs.port);
 
        struct http_shutdown_args sargs = { 5003, arguments.record };
        pthread_create(&http_shutdown_thr, NULL, 
                        http_shutdown_server, &sargs);
        printf("HTTP shutdown server started on port %i\n", sargs.port);
        
        struct http_chal_args cargs = { 5002, arguments.record };
        pthread_create(&http_chal_thr, NULL, 
                        http_chal_server, &cargs);
        printf("HTTP challenge server started on port %i\n", cargs.port);
       


        //acme_print_jwk();

 //       char* nonce;
      
        setvbuf (stdout, NULL, _IONBF, BUFSIZ);
        acme_get_resources();

        // TODO remove
        struct string_node* copy = string_list_copy(arguments.domain_list);
        char buf[512] = {0};
        copy = string_list_pop_back(copy, buf, sizeof(buf));
        if (buf[0] == '*'){
                //printf("Detected wildcard domain, removing.\n");
                //arguments.domain_list = 
                  //      string_list_pop_back(arguments.domain_list, NULL, 0);
        }

        enum acme_validation method = ACME_VALIDATION_DNS;
        if (!(strcmp(arguments.challenge_type, "dns01"))){
                method = ACME_VALIDATION_DNS;        
        }
        else if (!(strcmp(arguments.challenge_type, "http01"))){
                method = ACME_VALIDATION_HTTP; 
        }
        while ((acme_cert_fsm(&key, arguments.domain_list, method) == 0) 
                && !int_shutdown);

        if (arguments.revoke){
                printf("Revoking certificate.\n");
                acme_revoke_cert(&key, "cert.crt");          
        }

        struct https_args hargs = { 5001, arguments.record };
        pthread_create(&https_cert_thr, NULL, 
                        https_cert_server, &hargs);
        printf("HTTPS certificate server started on port %i\n", hargs.port);

        printf("All done, waiting for GET /shutdown\n");

        pthread_join(dns_thr, &dns_thr_result);
        pthread_join(http_shutdown_thr, &http_shutdown_thr_result);
        pthread_join(http_chal_thr, &http_chal_thr_result);
        pthread_join(https_cert_thr, &https_cert_thr_result);
#ifdef CONFIG_LOG_FILE       
        fflush(logf);
        fclose(logf);
#endif
        printf("Goodbye!\n");
        return 0;
}

