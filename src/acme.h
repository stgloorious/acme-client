/** 
 * @file acme.c
 * @brief ACME client core functionality
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

struct acme_jwk{
        char* kty;
        char* crv;
        char* x;
        char* y;
};

struct acme_header {
        char* alg;
        struct acme_jwk _jwk;
        char* jwk;
        char* kid;
        char* nonce;
        char* url;
};

struct acme_server {
        char** resources; // Array of resource URLs, uses acme_rsrc as index 
        char* ca_cert; // CA certificate used to sign the server's HTTPS cert
        
        // TODO implement
        char* nonce; // nonce included in every HTTP POST
};

enum acme_rsrc { ACME_RES_DIR, 
                 ACME_RES_KEYCHANGE, 
                 ACME_RES_NEW_ACC, 
                 ACME_RES_NEW_NONCE, 
                 ACME_RES_NEW_ORDER,
                 ACME_RES_NEW_AUTHZ,
                 ACME_RES_REVOKE_CERT,
                 ACME_RES_ORDER_LIST,
                 ACME_NUMBER_OF_RES }; // This must always be the last entry

enum acme_validation { ACME_VALIDATION_HTTP, ACME_VALIDATION_DNS };

#define ACME_MAX_NONCE_LENGTH 64

void acme_print_jwk();

struct acme_server* acme_server_new();

int8_t acme_server_delete(struct acme_server* server);

int8_t acme_server_add_resource( struct acme_server* server, 
                                 enum acme_rsrc resource,
                                 char* url );
int8_t acme_server_add_cert( struct acme_server* server, char* ca_cert);

int8_t acme_cert_fsm( EVP_PKEY** key, 
                      struct acme_server* server,
                      struct string_node* domain_list,
                      enum acme_validation validation_method );

int8_t acme_new_acc(EVP_PKEY** key, struct acme_server* server);

int8_t acme_new_order(EVP_PKEY** key, struct acme_server* server,
                struct string_node* domain_list,
                struct string_node** authz_list);

int8_t acme_get_chal(EVP_PKEY** key, struct acme_server* server, struct string_node* authz_list, 
                enum acme_validation chal_type);

int8_t acme_check_chal(EVP_PKEY** key, struct acme_server* server);

int8_t acme_resp_chal(EVP_PKEY** key, struct acme_server* server);

int8_t acme_add_root_cert(char* file, char* ca_cert);

int8_t acme_list_orders(EVP_PKEY** key, struct acme_server* server);

int8_t acme_finalize(EVP_PKEY** key, struct acme_server* server, struct string_node* domain_list);

int8_t acme_get_resources(struct acme_server* server);

int8_t acme_get_order_status(EVP_PKEY** key, struct acme_server* server);

int8_t acme_get_cert(EVP_PKEY** key, struct acme_server* server);

int8_t acme_revoke_cert(EVP_PKEY** key, struct acme_server* server, char* certfile);

int8_t acme_new_nonce(struct acme_server* server);

char* acme_write_header(struct acme_header* header);

void acme_write_payload(char* out, uint16_t len);

void acme_print_srv_response();

cJSON* acme_parse_srv_resp();

char* acme_get_token(char* url);

char* acme_get_token_dns();

void acme_cleanup();
