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

#include <curl/curl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <errno.h>

#include <cjson/cJSON.h>

#include "string.h"
#include "acme.h"
#include "crypt.h"
#include "b64.h"
#include "curl.h"

char* acme_nonce = NULL;
char acme_location[256];
char acme_kid[64];
char acme_finalize_url[512];
char acme_cert[128];
char acme_cert_chain[8192] = "";
char acme_root_cert[2048];
char acme_thumbprint[] = "kIObNDHaCoT9fXlDfWeLArEgfRon9f52a2DGE3SO4sM";

char acme_dns_token[512];
char acme_dns_digest[512];

struct string_node* acme_authz_list;
struct string_node* acme_chal_url_list;
struct string_node* acme_chal_token_list;


enum acme_state { ACME_STATE_IDLE, ACME_STATE_GET_ACC, 
        ACME_STATE_NEW_ORDER,
        ACME_STATE_GET_CHAL, ACME_STATE_RESP_CHAL, 
        ACME_STATE_CHECK_CHAL, ACME_STATE_FINALIZE,
        ACME_STATE_WAIT_FOR_CERT, ACME_STATE_GET_CERT };

enum acme_state acme_fsm_state = ACME_STATE_GET_ACC;

static char* acme_srv_response = NULL;

struct acme_server* acme_server_new(){
        struct acme_server* server = malloc(sizeof(struct acme_server));
        server->resources = calloc(ACME_NUMBER_OF_RES, sizeof(char*));
        server->ca_cert = NULL;
        server->nonce = NULL;
        return server;
}
int8_t acme_server_delete(struct acme_server* server){
        if (server->ca_cert != NULL){
                free(server->ca_cert);
        }
        for (uint8_t i = 0; i < ACME_NUMBER_OF_RES; i++){
                if (server->resources[i] != NULL){
                        free(server->resources[i]);
                }
        }
        free(server->resources);
        free(server);
        return 0;
}
int8_t acme_server_add_resource( struct acme_server* server, 
                                 enum acme_rsrc resource,
                                 char* url ){
        assert(url != NULL);
        server->resources[resource] = malloc(strlen(url)+1);
        strcpy(server->resources[resource], url);
        return 0; 
}
int8_t acme_server_add_cert( struct acme_server* server, char* ca_cert) {
        if(access(ca_cert, R_OK)){
                fprintf(stderr, "Error reading certificate file \"%s\": %s\n",
                                ca_cert, strerror(errno));
                return -1;
        }
        server->ca_cert = malloc(strlen(ca_cert)+1);
        strcpy(server->ca_cert, ca_cert);
        return 0;
}

int8_t acme_cert_fsm (  EVP_PKEY** key, 
                        struct acme_server* server, 
                        struct string_node* domain_list, 
                        enum acme_validation validation_method ){
        cJSON* resp;
        cJSON* status;
        cJSON* cert;
        switch(acme_fsm_state){
                case ACME_STATE_IDLE:
                        return 0;
                        break;
                case ACME_STATE_GET_ACC:
                        printf("Requesting account.\n");
                        if (!acme_new_acc(key, server)) {
                                acme_fsm_state = ACME_STATE_NEW_ORDER;
                        }
                        break;
                case ACME_STATE_NEW_ORDER:
                        acme_new_order(key, server, domain_list, &acme_authz_list);
                        resp = acme_parse_srv_resp();
                        status = cJSON_GetObjectItemCaseSensitive
                                (resp, "status"); 
                        if (cJSON_IsString(status)){
                                if (!strcmp(status->valuestring, "pending")){
                                        printf("Created new order %s.\n", acme_location);
                                        acme_fsm_state = ACME_STATE_GET_CHAL;
                                }
                        }
                        else {
                                acme_fsm_state = ACME_STATE_GET_ACC;
                                sleep(1);
                        }
                        break;
                case ACME_STATE_GET_CHAL:
                        printf("Getting challenges.\n");
                        acme_get_chal(key, server, acme_authz_list, validation_method);
                        resp = acme_parse_srv_resp();
                        status = cJSON_GetObjectItemCaseSensitive
                                (resp, "status"); 
                        if (cJSON_IsString(status)){
                                if (!strcmp(status->valuestring, "pending")){
                                        acme_fsm_state = ACME_STATE_RESP_CHAL;
                                }
                                if (!strcmp(status->valuestring, "valid")){
                                        acme_fsm_state = ACME_STATE_CHECK_CHAL;
                                }
                        }
                        break;
                case ACME_STATE_RESP_CHAL:
                        printf("Responding to challenges.\n");
                        acme_resp_chal(key, server);
                        resp = acme_parse_srv_resp();
                        status = cJSON_GetObjectItemCaseSensitive
                                (resp, "status"); 
                        if (cJSON_IsString(status)){
                                if (!strcmp(status->valuestring, "pending")){
                                        acme_fsm_state = 
                                                ACME_STATE_CHECK_CHAL;
                                }
                        }
                        else {
                                acme_fsm_state = ACME_STATE_GET_CHAL;
                        }
                        break;
                case ACME_STATE_CHECK_CHAL:
                        printf("Checking challenge state.\n");
                        
                        switch (acme_check_chal(key, server)){
                                case 0:
                                        acme_fsm_state = ACME_STATE_FINALIZE;
                                        break;
                                case -1: 
                                        break;
                                case -2: 
                                        acme_fsm_state = ACME_STATE_GET_CHAL;
                                        break;
                        }
                        sleep(1);

                        break;
                case ACME_STATE_FINALIZE:
                        printf("Challenges successful, finalizing.\n");
                        acme_finalize(key, server, domain_list);
                        resp = acme_parse_srv_resp();
                        status = cJSON_GetObjectItemCaseSensitive
                                (resp, "status"); 
                        if (cJSON_IsString(status)){
                                if (!strcmp(status->valuestring, "processing")){
                                        acme_fsm_state = 
                                                ACME_STATE_WAIT_FOR_CERT;
                                        return 0;
                                }
                        }
                        else {
                                acme_fsm_state = ACME_STATE_CHECK_CHAL;
                        }
                        sleep(1);
                        return 0;
                        break;
                case ACME_STATE_WAIT_FOR_CERT:
                        printf("Waiting for server to issue certificate.\n");
                        acme_get_order_status(key, server);
                        resp = acme_parse_srv_resp();
                        status = cJSON_GetObjectItemCaseSensitive
                                (resp, "status"); 
                        cert = cJSON_GetObjectItemCaseSensitive
                                (resp, "certificate"); 
                        if (cJSON_IsString(status) && cJSON_IsString(cert)){
                                if (!strcmp(status->valuestring, "valid")) {
                                        acme_fsm_state = 
                                                ACME_STATE_GET_CERT;
                                        strcpy(acme_cert, cert->valuestring);
                                        return 0;
                                }
                        }
                        sleep(1);
                        return 0;
                case ACME_STATE_GET_CERT:
                        printf("Certificate is ready.\n");
                        acme_get_cert(key, server);
                        acme_fsm_state = ACME_STATE_GET_ACC;
                       
                        acme_add_root_cert("cert.crt", server->ca_cert);

                        sleep(1);
                        FILE* fd;
                        fd = fopen("cert.crt","w");
                        fprintf(fd,"%s",acme_cert_chain);
                        fclose(fd);
                        printf("Certificate saved to cert.crt\n");
                        return 1;
                        break;
                default:
                        return -1;
        }
        return 0;
}

size_t acme_new_nonce_header_callback
(char* buf, size_t size, size_t nitems, void* data){ 
        if (!strncmp("Replay-Nonce", buf, 12)) {
                if (!acme_nonce){
                        acme_nonce = malloc(size * nitems - 13);
                }
                strcpy(acme_nonce, buf+14);
        }
        return nitems * size;
}

size_t acme_new_acc_header_callback
(char* buf, size_t size, size_t nitems, void* data){ 
        if (!strncmp("Location", buf, 8)) {
                strcpy(acme_location, buf+10);
                acme_location[strlen(acme_location) - 2] = '\0';
        }
        if (!strncmp("Replay-Nonce", buf, 12)) {
                strcpy(acme_nonce, buf+14);
                acme_nonce[strlen(acme_nonce) - 2] = '\0';
        }
return nitems * size;
}


size_t acme_write_callback(char *ptr, size_t size, 
                size_t nmemb, void *userdata) {
        //assert(acme_srv_response == NULL);
        //TODO fix
        if (acme_srv_response != NULL){
                printf("WARNING: Potential memory leak, "
                                "acme_srv_response != NULL\n");
                free(acme_srv_response);
                acme_srv_response=NULL;
        }

        acme_srv_response = malloc(size*nmemb+1);
        memcpy(acme_srv_response,ptr,nmemb);
        acme_srv_response[nmemb] = '\0';
        //printf("called write_callback:\n%p\n%s\n",
        //                acme_srv_response,acme_srv_response);
        return size*nmemb;  
}

size_t acme_cert_callback(char *ptr, size_t size, 
                size_t nmemb, void *userdata) {
        sprintf(acme_cert_chain+strlen(acme_cert_chain), "%s", ptr);
        return size*nmemb;  
}

size_t acme_root_cert_callback(char *ptr, size_t size, 
                size_t nmemb, void *userdata) {
        sprintf(acme_root_cert+strlen(acme_root_cert), "%s", ptr);
        return size*nmemb;  
}

int8_t acme_new_acc(EVP_PKEY** key, struct acme_server* server){
        /* if no nonce is available, request a new one */
        if (acme_nonce == NULL) {
                if (acme_new_nonce(server)) {
                        return -1;
                }
        }

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                  "\"x\":\"UECgzSZsrPD_B1drn3AaFHk3BujhFVy_SdMYm01SC7w\","
                  "\"y\":\"ec-zCqPse3--Nrgr5rjzfOzKO02sf9tLeLJGNxl3fGs\"}";
        hdr.nonce = acme_nonce;
        hdr.url = "https://pebble:14000/sign-me-up";
        hdr.kid = NULL;
        char* header = acme_write_header(&hdr);
        char payload[] = "{\"termsOfServiceAgreed\":true}";

        uint16_t header_len = (strlen(header) + 1) * 1.5;
        char* header64 = malloc(header_len);
        base64url((uint8_t*)header,header64,strlen(header),header_len);
        
        uint16_t payload_len = (strlen(payload) + 1) * 1.5;
        char* payload64 = malloc(payload_len);
        base64url((uint8_t*)payload,payload64,strlen(payload),payload_len);

        char* token2sign = malloc(header_len + payload_len + 1);
        sprintf(token2sign,"%s.%s",header64,payload64);

        uint16_t token_len = header_len + payload_len + 1 + 32;
        char* token = malloc(token_len);
        crypt_sign(token2sign, *key, token, token_len);

        uint16_t body_len = header_len + payload_len + token_len;
        body_len += strlen( "{\"protected\":\"\","
                            "\"payload\":\"\","
                            "\"signature\":\"\"}" );
        char* body = malloc(body_len);
        sprintf(body, "{\"protected\":\"%s\","
                      "\"payload\":\"%s\","
                      "\"signature\":\"%s\"}", header64, payload64, token);

        free(header);
        free(header64);
        free(payload64);
        free(token2sign);
        free(token);

        curl_post(server->resources[ACME_RES_NEW_ACC], body, acme_write_callback,
                        acme_new_acc_header_callback, NULL, server->ca_cert); 

        free(body);
        assert(acme_srv_response != NULL);
        cJSON* srv_resp = cJSON_Parse(acme_srv_response);
        if (srv_resp == NULL){
                const char* err = cJSON_GetErrorPtr();
                if (err != NULL){
                        printf("JSON parse error in server response: err\n");
                }
                return -1;
        }
        cJSON* status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status"); 
        cJSON* orders = cJSON_GetObjectItemCaseSensitive(srv_resp, "orders");
        if (cJSON_IsString(status) && cJSON_IsString(orders)){
                if (strcmp(status->valuestring,"valid")){
                        printf("Server response: status = %s\n", status->valuestring);
                }
                printf("Account is valid.\n");
                acme_server_add_resource(server, ACME_RES_ORDER_LIST, orders->valuestring);
        }
        else {
                printf("Server response parse error\n");   
                cJSON_Delete(srv_resp);
                free(acme_srv_response);
                acme_srv_response = NULL;
                return -1;
        }
        cJSON_Delete(srv_resp);
        free(acme_srv_response);
        acme_srv_response = NULL;
        return 0;
}

void acme_print_srv_response(){
        assert(acme_srv_response != NULL); 
        printf("Server response:\n%s\n", acme_srv_response);
}

cJSON* acme_parse_srv_resp(){
        assert(acme_srv_response != NULL);
        cJSON* srv_resp = cJSON_Parse(acme_srv_response);
        free(acme_srv_response);
        acme_srv_response = NULL;
        return srv_resp;
}


int8_t acme_new_order(EVP_PKEY** key, struct acme_server* server, struct string_node* domain_list,
                struct string_node** authz_list){
        char signature[512] = {0};
        char post[2048] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_location;
        strcpy(acme_kid, hdr.kid);
        hdr.nonce = acme_nonce;
        hdr.url = server->resources[ACME_RES_NEW_ORDER];
        char* header = acme_write_header(&hdr);

        char payload[1024];
        //strcpy(payload, "{\"identifiers\":["
                       //"{\"type\":\"dns\","
                       // "\"value\":\"example.com\"},"
        //                "{\"type\":\"dns\","
        //                "\"value\":\"example.com\"}]}");
        
        cJSON* id;
        char domain[64];

        cJSON* ids = cJSON_CreateArray();
        cJSON* identifiers = cJSON_CreateObject();
      
        assert(domain_list != NULL);
        struct string_node* domains = string_list_copy(domain_list);
        while (domains != NULL) {
                domains = string_list_pop_back(domains, 
                                domain, sizeof(domain));
                printf("Got %s from list, head is %p\n", domain, domains);
                id = cJSON_CreateObject();
                cJSON_AddItemToObject(id, "type", cJSON_CreateString("dns"));
                cJSON_AddItemToObject(id, "value", cJSON_CreateString(domain));
                cJSON_AddItemToArray(ids, id);
        }
        cJSON_AddItemToObject(identifiers, "identifiers", ids);
        
        strcpy(payload, cJSON_Print(identifiers));

        cJSON_Delete(identifiers);

        char msg[2048];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[512];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);

        curl_post(server->resources[ACME_RES_NEW_ORDER], post, acme_write_callback,
                        acme_new_acc_header_callback, NULL, server->ca_cert);
                
        assert(acme_srv_response != NULL);
        cJSON* srv_resp = cJSON_Parse(acme_srv_response);
        if (srv_resp == NULL){
                const char* err = cJSON_GetErrorPtr();
                if (err != NULL){
                        printf("JSON parse error in server response: err\n");
                }
                return -1;
        }
        //acme_print_srv_response(acme_srv_response);
        cJSON* finalize = cJSON_GetObjectItemCaseSensitive(srv_resp, "finalize"); 
        cJSON* authz = cJSON_GetObjectItemCaseSensitive(srv_resp, "authorizations");
        if (cJSON_IsString(finalize)){
                strcpy(acme_finalize_url, finalize->valuestring);
        }
        else {
                printf("Server response parse error\n");
                acme_print_srv_response();
                cJSON_Delete(srv_resp);
                free(acme_srv_response);
                acme_srv_response = NULL;
                return -1;
        }
        cJSON* auth;
        cJSON_ArrayForEach(auth, authz) {
                if (cJSON_IsString(auth)){
                        char auth_url[128];
                        strcpy(auth_url, auth->valuestring);
                        *authz_list = string_list_append(*authz_list, auth_url);            
                        printf("Appended %s to head %p\n", auth_url, *authz_list);
                }
                else {
                        printf("Auth parse error\n");
                }
        }
        cJSON_Delete(srv_resp);
        return 0;
}

int8_t acme_get_chal( EVP_PKEY** key, 
                      struct acme_server* server,
                      struct string_node* authz_list,
                      enum acme_validation chal_type ){

        char signature[512] = {0};
        char post[2048] = {0};

   
        assert(authz_list != NULL);
        struct string_node* authz = string_list_copy(authz_list);
        string_list_delete(acme_chal_url_list);
        acme_chal_url_list = NULL;
        string_list_delete(acme_chal_token_list);
        acme_chal_token_list = NULL;
        while (authz != NULL){
                char auth[512];
                authz = string_list_pop_back(authz, 
                                auth, sizeof(auth));
                printf("Got %s from list, head is %p\n", auth, authz);
               
                struct acme_header hdr;
                hdr.alg = "ES256";
                hdr.kid = acme_kid;
                hdr.nonce = acme_nonce;
                hdr.url = auth;

                char* header = acme_write_header(&hdr);

                char payload[1024];
                strcpy(payload, "");

                char msg[2048];
                char header64[512];
                base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
                
                char payload64[512];
                base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

                sprintf(msg,"%s.%s",header64,payload64);
                crypt_sign(msg,*key,signature,sizeof(signature));

                sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                                "\"signature\":\"%s\"}",
                                header64,payload64,signature);

                            curl_post(auth, post, acme_write_callback, 
                                acme_new_acc_header_callback, NULL, server->ca_cert);
                        
                assert(acme_srv_response != NULL);
                cJSON* srv_resp = cJSON_Parse(acme_srv_response);
                if (srv_resp == NULL){
                        const char* err = cJSON_GetErrorPtr();
                        if (err != NULL){
                                printf("JSON parse error"
                                                "in server response: err\n");
                        }
                        return -1;
                }
                //acme_print_srv_response(acme_srv_response);
                cJSON* challenges = cJSON_GetObjectItemCaseSensitive
                        (srv_resp, "challenges"); 
                cJSON* wildcard = cJSON_GetObjectItemCaseSensitive
                        (srv_resp, "wildcard"); 
                int is_wildcard=0;
                if (cJSON_IsBool(wildcard)){
                        if (wildcard->valueint){
                                printf("This is a wildcard domain!\n");
                                is_wildcard=1;
                        }
                }
                cJSON* chal;
                cJSON_ArrayForEach(chal, challenges) {
                        cJSON* type = 
                                cJSON_GetObjectItemCaseSensitive(chal, "type"); 
                        cJSON* url = 
                                cJSON_GetObjectItemCaseSensitive(chal, "url");
                        cJSON* token = 
                                cJSON_GetObjectItemCaseSensitive(chal, "token");
                       
                        if (!is_wildcard){
                                if (!(strcmp(type->valuestring, "http-01"))){
                                        acme_chal_url_list = string_list_append
                                                (acme_chal_url_list, url->valuestring);
                                        string_list_print(acme_chal_url_list);
                                        acme_chal_token_list = string_list_append
                                                (acme_chal_token_list, token->valuestring);
                                        string_list_print(acme_chal_token_list);
                                        break;
                                }
                        }
                        else {
                                 if (!(strcmp(type->valuestring, "dns-01"))){
                                        acme_chal_url_list = string_list_append
                                                (acme_chal_url_list, url->valuestring);
                                        string_list_print(acme_chal_url_list);
                                        acme_chal_token_list = string_list_append
                                                (acme_chal_token_list, token->valuestring);
                                        strcpy(acme_dns_token, token->valuestring);
                                        strcpy(acme_dns_digest,acme_get_token_dns());
                                        printf("Token is ready at %p\n", acme_dns_digest);
                                        string_list_print(acme_chal_token_list);
                                        break;
                                }

                        }
                }
                cJSON_Delete(srv_resp);
        }
        return 0;
}
char* acme_get_token(char* url) {
        char* token = malloc(256);
        printf("Replying to url %s with token ", url);
        strcpy(token, url+strlen("/.well-known/acme-challenge/")); 
        strcpy(token+strlen(token),".");
        strcpy(token+strlen(token),acme_thumbprint);
        printf("%s\n", token);

        return token; 
}
char* acme_get_token_dns() {
        char* token = malloc(512);
        char* digest = malloc(32);
        strcpy(token, acme_dns_token); 
        printf("Using token %s\n", token);
        strcpy(token+strlen(token),".");
        strcpy(token+strlen(token),acme_thumbprint);
        SHA256(token, strlen(token), digest);
        base64url(digest, token, 32, 512);
        printf("DNS token: *%s* at %p\n", token, token);
        return token; 
}
int8_t acme_resp_chal(EVP_PKEY** key, struct acme_server* server){
        char signature[512] = {0};
        char post[2048] = {0};

        char header[1024] = {0};
        assert(acme_chal_url_list != NULL);
        struct string_node* chal_list = string_list_copy(acme_chal_url_list);
        while (chal_list != NULL) {

                char chal_url[256] = {0};
                chal_list = string_list_pop_back(chal_list, 
                                chal_url, sizeof(chal_url));

                printf("Got %s from list, head is %p\n", chal_url, chal_list);
                struct acme_header hdr;
                hdr.alg = "ES256";
                hdr.kid = acme_kid;
                hdr.nonce = acme_nonce;
                hdr.url = chal_url;

                char* header = acme_write_header(&hdr);

                char payload[1024];
                strcpy(payload, "{}");

                char msg[2048];
                char header64[512];
                base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
                
                char payload64[512];
                base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

                sprintf(msg,"%s.%s",header64,payload64);
                crypt_sign(msg,*key,signature,sizeof(signature));

                sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                                "\"signature\":\"%s\"}",
                                header64,payload64,signature);

                printf("acme_chal_url: %s\n",  chal_url);
                curl_post(chal_url, post, acme_write_callback, 
                                acme_new_acc_header_callback, NULL, server->ca_cert);
                        
                assert(acme_srv_response != NULL);
                cJSON* srv_resp = cJSON_Parse(acme_srv_response);
                if (srv_resp == NULL){
                        const char* err = cJSON_GetErrorPtr();
                        if (err != NULL){
                                printf("JSON parse error in server response: err\n");
                        }
                        return -1;
                }
                //acme_print_srv_response(acme_srv_response);
              /*  cJSON* challenges = 
                        cJSON_GetObjectItemCaseSensitive(srv_resp, "challenges"); 
                cJSON* chal;
                cJSON_ArrayForEach(chal, challenges) {
                        cJSON* type = cJSON_GetObjectItemCaseSensitive(chal, "type");
                        if (cJSON_IsString(type)){
                                printf("Type: %s\n", type->valuestring);
                        } 
                        cJSON* url = cJSON_GetObjectItemCaseSensitive(chal, "url");
                        if (cJSON_IsString(type)){
                                printf("URL: %s\n", url->valuestring);
                        } 
                        cJSON* token = cJSON_GetObjectItemCaseSensitive(chal, "token");
                        if (cJSON_IsString(type)){
                                printf("Token: %s\n", token->valuestring);
                        }
                        if (!(strcmp(type->valuestring, "http-01"))){
                                strcpy(acme_chal_url, url->valuestring);
                                strcpy(acme_chal_token, token->valuestring); 
                                break;
                        }
                }
                cJSON_Delete(srv_resp);*/
        }
        //string_list_delete(chal_list);
        return 0;
}
int8_t acme_finalize(EVP_PKEY** key, struct acme_server* server, struct string_node* domain_list){
        char signature[4096] = {0};
        char post[16384] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_kid;
        hdr.nonce = acme_nonce;
        hdr.url = acme_finalize_url;

        char* header = acme_write_header(&hdr);

        EVP_PKEY* csr_key = NULL;
        X509_REQ* csr;
        char csr_pem[4096] = {0};
        crypt_new_csr(&csr_key, &csr, csr_pem, sizeof(csr_pem), domain_list);
        crypt_strip_csr(csr_pem);
        b64_normal2url(csr_pem);

        FILE* keyfile;
        keyfile = fopen("client.key", "w");
        PEM_write_PKCS8PrivateKey(keyfile, csr_key, 
                        EVP_des_ede3_cbc(), NULL, 0, 0, "password");
        fclose(keyfile);

        char payload[4096];
        strcpy(payload, "{\"csr\":\"");
        strcpy(payload+strlen(payload),csr_pem);
        strcpy(payload+strlen(payload), "\"}");

        char msg[8192];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[4096];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);
 
        curl_post(acme_finalize_url, post, acme_write_callback, 
                        acme_new_acc_header_callback, NULL, server->ca_cert);
        return 0;
}
int8_t acme_get_order_status(EVP_PKEY** key, struct acme_server* server){
        char signature[4096] = {0};
        char post[16384] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_kid;
        hdr.nonce = acme_nonce;
        hdr.url = acme_location;
        char* header = acme_write_header(&hdr);

        char payload[4096];
        strcpy(payload, "");
        
        char msg[8192];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[4096];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);
 
        curl_post(acme_location, post, acme_write_callback,
                        acme_new_acc_header_callback, NULL, server->ca_cert);
        return 0;
}
int8_t acme_check_chal(EVP_PKEY** key, struct acme_server* server){
        char signature[512] = {0};
        char post[2048] = {0};

        struct acme_header hdr;
        
        if (acme_chal_url_list == NULL){
                return -2;
        }
        struct string_node* chal_list = string_list_copy(acme_chal_url_list);
        while (chal_list != NULL) {
             
                char chal_url[256] = {0};
                chal_list = string_list_pop_back(chal_list, 
                                chal_url, sizeof(chal_url));

                printf("Got %s from list, head is %p\n", chal_url, chal_list);
   
                hdr.alg = "ES256";
                hdr.kid = acme_kid;
                hdr.nonce = acme_nonce;
                hdr.url = chal_url;
                char* header = acme_write_header(&hdr);

                char payload[1024];
                strcpy(payload, "");

                char msg[2048];
                char header64[512];
                base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
                
                char payload64[512];
                base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

                sprintf(msg,"%s.%s",header64,payload64);
                crypt_sign(msg,*key,signature,sizeof(signature));

                sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                                "\"signature\":\"%s\"}",
                                header64,payload64,signature);


                curl_post(chal_url, post, acme_write_callback, 
                                acme_new_acc_header_callback, NULL, server->ca_cert);
        
                cJSON* resp = acme_parse_srv_resp();
                cJSON* status = cJSON_GetObjectItemCaseSensitive(resp, "status"); 
                if (cJSON_IsString(status)){
                        if (!strcmp(status->valuestring, "valid")){
                                printf("Challenge %s is valid, removing it "
                                                "from list.\n", chal_url);  
                                acme_chal_url_list = string_list_pop_back
                                        (acme_chal_url_list, NULL, 0);
                                if (acme_chal_url_list == NULL){
                                        return 0;
                                }
                        }
                        else {
                                return -2;
                        }
                }
        }
        return -1;
}

int8_t acme_list_orders(EVP_PKEY** key, struct acme_server* server){
        char signature[512] = {0};
        char post[2048] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_location;
        hdr.nonce = acme_nonce;
        hdr.url = server->resources[ACME_RES_ORDER_LIST];
        char* header = acme_write_header(&hdr);
        printf("Header is \n%s\n", header);

        char payload[1024];
        strcpy(payload, "{}");
        printf("Payload is \n%s\n", payload);

        char msg[2048];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[512];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);

        curl_post(server->resources[ACME_RES_ORDER_LIST], post, acme_write_callback, 
                        acme_new_acc_header_callback, NULL, server->ca_cert);
        return 0;
}

int8_t acme_add_root_cert(char* file, char* ca_cert){
        curl_get("https://pebble:15000/roots/0", NULL, acme_root_cert_callback, ca_cert); 
        //printf("Root cert:\n%s\n", acme_root_cert);
        char* p = strstr(acme_cert_chain, "-----END CERTIFICATE-----");
        p += strlen("-----END CERTIFICATE-----");
        p = strstr(p, "-----END CERTIFICATE-----");
        p += strlen("-----END CERTIFICATE-----");
        strcpy(p, "\n");
        strcpy(p+1, acme_root_cert);
        return 0;
}

int8_t acme_get_cert(EVP_PKEY** key, struct acme_server* server){
        char signature[512] = {0};
        char post[2048] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_kid;
        hdr.nonce = acme_nonce;
        hdr.url = acme_cert;
        char* header = acme_write_header(&hdr);

        char payload[1024];
        strcpy(payload, "");

        char msg[2048];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[512];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);

        char* headers = "Accept: application/pem-certificate-chain";
        curl_post(acme_cert, post,  acme_cert_callback, 
                        acme_new_acc_header_callback, headers, server->ca_cert);
        free(acme_srv_response);
        acme_srv_response=NULL;
        return 0;
}

int8_t acme_revoke_cert(EVP_PKEY** key, struct acme_server* server, char* certfile){
        char signature[4096] = {0};
        char post[16384] = {0};

        struct acme_header hdr;
        hdr.alg = "ES256";
        hdr.kid = acme_kid;
        hdr.nonce = acme_nonce;
        hdr.url = server->resources[ACME_RES_REVOKE_CERT];
        char* header = acme_write_header(&hdr);

        char payload[4096] = {0};
        strcpy(payload, "{\"certificate\":\"");
        char pem_cert[2048];
        FILE* cfile;
        cfile = fopen("cert.crt", "r");
        assert(cfile != NULL); 
        int len = fread(pem_cert, sizeof(pem_cert),
                        sizeof(char), cfile);
        assert(len > 0);
        fclose(cfile); 

        crypt_strip_cert(pem_cert);
        b64_normal2url(pem_cert);
        strcpy(payload+strlen(payload), pem_cert);
        strcpy(payload+strlen(payload), "\"}");
        printf("cert:\n%s\n", payload);

        char msg[8192];
        char header64[512];
        base64url((uint8_t*)header,header64,strlen(header),sizeof(msg));
        
        char payload64[4096];
        base64url((uint8_t*)payload,payload64,strlen(payload),sizeof(msg));

        sprintf(msg,"%s.%s",header64,payload64);
        crypt_sign(msg,*key,signature,sizeof(signature));

        sprintf(post,"{\"protected\":\"%s\",\"payload\":\"%s\","
                        "\"signature\":\"%s\"}",
                        header64,payload64,signature);

        curl_post(server->resources[ACME_RES_REVOKE_CERT], post,
                        acme_write_callback, NULL, NULL, server->ca_cert);
        free(acme_srv_response);
        acme_srv_response=NULL;
        return 0;
}

int8_t acme_new_nonce(struct acme_server* server){
        curl_get(server->resources[ACME_RES_NEW_NONCE],
                        acme_new_nonce_header_callback, NULL, server->ca_cert);
        acme_nonce[strlen(acme_nonce) - 2] = '\0';
        return 0;
}

int8_t acme_get_resources(struct acme_server* server){
        if (curl_get(server->resources[ACME_RES_DIR], acme_new_nonce_header_callback, 
                                acme_write_callback, server->ca_cert) != 0){
                return -1;
        }
        cJSON* res = cJSON_Parse(acme_srv_response);
        cJSON* nonce = cJSON_GetObjectItemCaseSensitive(res, "newNonce");
        cJSON* acc = cJSON_GetObjectItemCaseSensitive(res, "newAccount");
        cJSON* order = cJSON_GetObjectItemCaseSensitive(res, "newOrder");
        cJSON* revoke = cJSON_GetObjectItemCaseSensitive(res, "revokeCert");
        cJSON* key_change = cJSON_GetObjectItemCaseSensitive(res, "key-change");

        acme_server_add_resource(server, ACME_RES_NEW_NONCE, nonce->valuestring);
        acme_server_add_resource(server, ACME_RES_NEW_ACC, acc->valuestring);
        acme_server_add_resource(server, ACME_RES_NEW_ORDER, order->valuestring);
        acme_server_add_resource(server, ACME_RES_REVOKE_CERT, revoke->valuestring);

        if (res != NULL) 
                cJSON_Delete(res);

        if (acme_srv_response){
                free(acme_srv_response);
                acme_srv_response = NULL;
        }
        return 0;
}


char* acme_write_header(struct acme_header* header){
        char* out;

        /* get length of header fields */
        uint16_t len = strlen(header->alg) + strlen(header->jwk)
                        + strlen(header->nonce) + strlen(header->url);
        /* add constant length of labels
         * note that the longer variant (kid) */
        len += strlen("{\"alg\":\"\","
                        "\"kid\":\"\","
                        "\"nonce\":\"\","
                        "\"url\":\"\"}");
        out = malloc(len+1); // +1 for null termination
                             
        /* kid and jwt field are mutually exclusive. */
        if (header->kid == NULL) {
                sprintf(out, "{\"alg\":\"%s\","
                        "\"jwk\":%s,"
                        "\"nonce\":\"%s\","
                        "\"url\":\"%s\"}", 
                        header->alg,header->jwk,header->nonce,header->url);
        }
        else {
                sprintf(out, "{\"alg\":\"%s\","
                        "\"kid\":\"%s\","
                        "\"nonce\":\"%s\","
                        "\"url\":\"%s\"}", 
                        header->alg,header->kid,header->nonce,header->url); 
        }
        return out;
}

void acme_cleanup() {
        if (acme_nonce != NULL){
                free(acme_nonce);
        }
}
