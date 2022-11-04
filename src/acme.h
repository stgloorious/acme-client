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

enum acme_validation { ACME_VALIDATION_HTTP, ACME_VALIDATION_DNS };


void acme_print_jwk();

int8_t acme_cert_fsm(EVP_PKEY** key, struct string_node* domain_list,
                enum acme_validation validation_method);

int8_t acme_new_acc(EVP_PKEY** key);

int8_t acme_new_order(EVP_PKEY** key, struct string_node* domain_list,
                struct string_node** authz_list);

int8_t acme_get_chal(EVP_PKEY** key, struct string_node* authz_list, 
                enum acme_validation chal_type);

int8_t acme_check_chal(EVP_PKEY** key);

int8_t acme_resp_chal(EVP_PKEY** key);

int8_t acme_add_root_cert(char* file);

int8_t acme_list_orders(EVP_PKEY** key);

int8_t acme_finalize(EVP_PKEY** key, struct string_node* domain_list);

int8_t acme_get_resources();

int8_t acme_get_order_status(EVP_PKEY** key);

int8_t acme_get_cert(EVP_PKEY** key);

int8_t acme_revoke_cert(EVP_PKEY** key, char* certfile);

int8_t acme_new_nonce(char* nonce_resource, char* nonce, uint8_t len);

void acme_write_header(char* out, uint16_t len, struct acme_header* header);

void acme_write_payload(char* out, uint16_t len);

void acme_print_srv_response();

cJSON* acme_parse_srv_resp();

char* acme_get_token(char* url);

char* acme_get_token_dns();

