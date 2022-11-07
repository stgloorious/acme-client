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
        arguments.server_cert = "";
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
                        string_list_pop_back(arguments.domain_list, buf, sizeof(buf));
                        printf("DOMAIN = %s\n", buf);
                }
                printf("DIR_URL = %s\n", arguments.dir_url);
                printf("record = %s\n", arguments.record);
                printf("revoke = %i\n", arguments.revoke);
                printf("ca_cert = %s\n", arguments.server_cert);
                printf("verbose = %i\n\n", arguments.verbose);
#endif
        printf("Using OpenSSL version: %s\n", OPENSSL_VERSION_TEXT); 
        }
         
        
        EVP_PKEY *key = NULL;
        crypt_new_key(&key);

        /* The only information we have about the ACME server is the dir 
         * resource. The other resource urls are obtained by sending a 
         * request to this dir resource 
         */
        struct acme_server* server = acme_server_new();
        acme_server_add_resource(server, ACME_RES_DIR, arguments.dir_url);
        if (acme_server_add_cert(server, arguments.server_cert) != 0) {
                acme_server_delete(server);
                acme_cleanup();
                EVP_PKEY_free(key);
                return -1;
        }
        if(acme_get_resources(server) != 0){
                fprintf(stderr, "Could not obtain ACME resource URLs.\n");
                acme_server_delete(server);
                acme_cleanup();
                EVP_PKEY_free(key);
                return -1;
        } 
        
        /* Request a new account, which is identified by our key */
        if (acme_new_acc(&key, server)) {
                fprintf(stderr, "Could not create account.\n");
        }
        
        acme_server_delete(server);
        acme_cleanup(); 
        EVP_PKEY_free(key);

        /*
        enum acme_validation method = ACME_VALIDATION_DNS;
        if (!(strcmp(arguments.challenge_type, "dns01"))){
                method = ACME_VALIDATION_DNS;        
        }
        else if (!(strcmp(arguments.challenge_type, "http01"))){
                method = ACME_VALIDATION_HTTP; 
        }
        while ((acme_cert_fsm(&key, server, arguments.domain_list, method) == 0) 
                && !int_shutdown);

        if (arguments.revoke){
                printf("Revoking certificate.\n");
                acme_revoke_cert(&key, server, "cert.crt");          
        }
*/
       // pthread_join(http_chal_thr, &http_chal_thr_result);
        return 0;
}

