/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of acme-client.
 *
 * acme-client is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 *
 * acme-client is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with acme-client. If not, see <https://www.gnu.org/licenses/>. 
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
#include <signal.h>
#include <cjson/cJSON.h>
#include <sys/stat.h>

#include "string.h"
#include "acme.h"
#include "crypt.h"
#include "b64.h"
#include "curl.h"
#include "types.h"
#include "err.h"

extern uint8_t verbose;
extern volatile sig_atomic_t int_shutdown;

char *acme_nonce = NULL;
char *acme_location = NULL;
char *acme_kid = NULL;
char *acme_cert_chain = NULL;
char *acme_thumbprint = NULL;

struct string_node *acme_authz_list;
struct string_node *acme_chal_url_list;
struct string_node *acme_chal_token_list;

enum acme_state {
	ACME_STATE_IDLE,
	ACME_STATE_GET_ACC,
	ACME_STATE_NEW_ORDER,
	ACME_STATE_GET_AUTH,
	ACME_STATE_AUTHORIZE,
	ACME_STATE_CHECK_AUTH,
	ACME_STATE_FINALIZE,
	ACME_STATE_WAIT_FOR_CERT,
	ACME_STATE_GET_CERT
};

enum acme_state acme_fsm_order_state = ACME_STATE_NEW_ORDER;
enum acme_state acme_fsm_validate_state = ACME_STATE_AUTHORIZE;
enum acme_state acme_fsm_cert_state = ACME_STATE_FINALIZE;

static char *acme_srv_response = NULL;

struct acme_server *acme_server_new()
{
	struct acme_server *server = malloc(sizeof(struct acme_server));
	server->resources = calloc(ACME_NUMBER_OF_RES, sizeof(char *));
	server->ca_cert = NULL;
	server->nonce = NULL;
	return server;
}
int8_t acme_server_delete(struct acme_server *server)
{
	if (server->ca_cert != NULL) {
		free(server->ca_cert);
	}
	for (uint8_t i = 0; i < ACME_NUMBER_OF_RES; i++) {
		if (server->resources[i] != NULL) {
			free(server->resources[i]);
		}
	}
	free(server->resources);
	free(server);
	return 0;
}
int8_t acme_server_add_resource(struct acme_server *server,
				enum acme_rsrc resource, char *url)
{
	assert(url != NULL);
	server->resources[resource] = malloc(strlen(url) + 1);
	strcpy(server->resources[resource], url);
	return 0;
}
int8_t acme_server_add_cert(struct acme_server *server, char *ca_cert)
{
	if (ca_cert == NULL) {
		server->ca_cert = NULL;
		return 0;
	}
	if (access(ca_cert, R_OK)) {
		ERROR("Error reading certificate file \"%s\": %s\n", ca_cert,
		      strerror(errno));
		return -1;
	}
	server->ca_cert = malloc(strlen(ca_cert) + 1);
	strcpy(server->ca_cert, ca_cert);
	return 0;
}

static enum acme_status acme_get_status(char *str)
{
	if (str == NULL) {
		return ACME_STATUS_UNKNOWN;
	}
	if (!(strcmp(str, "valid"))) {
		return ACME_STATUS_VALID;
	}
	if (!(strcmp(str, "pending"))) {
		return ACME_STATUS_PENDING;
	}
	if (!(strcmp(str, "ready"))) {
		return ACME_STATUS_READY;
	}
	if (!(strcmp(str, "processing"))) {
		return ACME_STATUS_PROCESSING;
	}
	if (!(strcmp(str, "invalid"))) {
		return ACME_STATUS_INVALID;
	}
	return ACME_STATUS_UNKNOWN;
}

int8_t acme_fsm_order(struct acme_account *client, struct acme_server *server,
		      struct string_node *domain_list)
{
	switch (acme_fsm_order_state) {
	case ACME_STATE_NEW_ORDER:
		acme_new_order(client, server, domain_list);
		if (client->order->status == ACME_STATUS_PENDING) {
			acme_fsm_order_state = ACME_STATE_GET_AUTH;
		} else if (client->order->status == ACME_STATUS_READY) {
			DEBUG("Order is ready.\n");
			acme_fsm_order_state = ACME_STATE_GET_AUTH;
		} else {
			DEBUG("Could not place order, retrying\n");
			sleep(1);
		}
		break;
	case ACME_STATE_GET_AUTH:
		DEBUG("Getting authorizations.\n");
		switch (acme_get_auth(client, server)) {
		case 0:
			DEBUG("Obtained all authorizations\n");
			acme_fsm_order_state = ACME_STATE_NEW_ORDER;
			return 1;
		case 1:
			DEBUG("Obtained all authorizations\n");
			acme_fsm_order_state = ACME_STATE_NEW_ORDER;
			return 2;
		default:
			ERROR("Authorization fetching failed, retrying.\n");
			sleep(1);
		}
		break;
	default:
		return -1;
	}
	return 0;
}
int8_t acme_fsm_validate(struct acme_account *client,
			 struct acme_server *server, enum acme_chal_type method)
{
	static uint8_t auth_retry_count = 0;
	switch (acme_fsm_validate_state) {
	case ACME_STATE_AUTHORIZE:
		acme_authorize(client, server, method);
		acme_fsm_validate_state = ACME_STATE_CHECK_AUTH;
		sleep(1);
		break;
	case ACME_STATE_CHECK_AUTH:
		DEBUG("Checking authorization state.\n");
		switch (acme_get_auth(client, server)) {
		case 0:
			auth_retry_count++;
			if (auth_retry_count == 5) {
				acme_fsm_validate_state = ACME_STATE_AUTHORIZE;
				DEBUG("Authorization are still not valid. "
				      "Trying again.\n");
			}
			break;
		case -1:
			DEBUG("Authorization is not ready yet.\n");
			sleep(1);
			return 0;
		}

		if (client->authz_list == NULL) {
			return 1;
		}
		sleep(2);
		return 0;
		break;
	default:
		return -1;
	}
	return 0;
}
int8_t acme_fsm_cert(struct acme_account *client, struct acme_server *server,
		     struct string_node *domain_list)
{
	switch (acme_fsm_cert_state) {
	case ACME_STATE_FINALIZE:
		DEBUG("Finalizing: Request server to issue cert.\n");
		int ret = acme_finalize(client, server, domain_list);
		if (ret == 0 || ret == 1) {
			acme_fsm_cert_state = ACME_STATE_WAIT_FOR_CERT;
		}
		sleep(1);
		return 0;
		break;
	case ACME_STATE_WAIT_FOR_CERT:
		DEBUG("Waiting for server to issue certificate.\n");
		if (acme_get_order_status(client, server)) {
			acme_fsm_cert_state = ACME_STATE_GET_CERT;
		}
		sleep(1);
		return 0;
	case ACME_STATE_GET_CERT:
		DEBUG("Certificate is ready.\n");
		acme_get_cert(client, server);
		acme_cert_chain = malloc(strlen(acme_srv_response) + 1);
		strcpy(acme_cert_chain, acme_srv_response);
		free(acme_srv_response);
		acme_srv_response = NULL;

		/* Set permissions of certificate to 0666 */
		umask(~(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |
			S_IWOTH));
		FILE *fd;
		fd = fopen("cert.crt", "w");
		fprintf(fd, "%s", acme_cert_chain);
		fclose(fd);
		NOTICE("Certificate saved to cert.crt\n");
		acme_fsm_validate_state = ACME_STATE_GET_ACC;
		free(acme_cert_chain);
		return 1;
		break;
	default:
		return -1;
	}
	return 0;
}

size_t acme_header_cb(char *buf, size_t size, size_t nitems, void *packet_info)
{
	/* The location header points to the url of the 
         * created object. E.g. after creating an account,
         * location will contain the url that points to 
         * that account object */
	if (!strncmp("Location", buf, 8)) {
		/* this is way to much memory but it sure is enough */
		acme_location = realloc(acme_location, size * nitems);
		strcpy(acme_location, buf + 10);
		acme_location[strlen(acme_location) - 2] = '\0';
	}

	/* The replay nonce is contained in every response 
         * and should always be used for the next request */
	if (!strncmp("Replay-Nonce", buf, 12)) {
		if (acme_nonce == NULL) {
			acme_nonce = calloc(nitems + 1, size);
		}
		strcpy(acme_nonce, buf + 14);
		acme_nonce[strlen(acme_nonce) - 2] = '\0';
	}

	/* The content length is used to allocate a buffer,
         * which is then filled with data by the write_cb.
         * This is necessary because write_cb might be called
         * several times for a single packet */
	if (!strncmp("Content-Length", buf, 14)) {
		int32_t len = atoi(buf + 16);
		struct curl_packet_info *packet =
			(struct curl_packet_info *)packet_info;
		packet->buffer = (len != 0) ? malloc(len) : NULL;
		packet->received = 0;
		packet->total_length = len;
		packet->chunked = 0;
	} /* The server might use chunked transfer, meaning the 
           * server is not aware of the length of the data yet.
           * The transfer ends with a zero-length chunk */
	else if (!strncmp("Transfer-Encoding: chunked", buf, 26)) {
		struct curl_packet_info *packet =
			(struct curl_packet_info *)packet_info;
		packet->buffer = NULL;
		packet->received = 0;
		packet->total_length = 0;
		packet->chunked = 1;
	}

	return nitems * size;
}

size_t acme_write_cb(char *ptr, size_t size, size_t nmemb, void *packet_info)
{
	/* This struct contains information about the current packet
         * this write_cb corresponds to. Most of the time all of the
         * data will be received with a single call to wb, but this is
         * not always the case */
	struct curl_packet_info *packet =
		(struct curl_packet_info *)packet_info;

	if (packet->chunked) {
		acme_srv_response = realloc(
			acme_srv_response, packet->received + size * nmemb + 1);
		memcpy(acme_srv_response + packet->received, ptr, size * nmemb);
		packet->received += size * nmemb;
		*(acme_srv_response + packet->received) = '\0';

		return size * nmemb;
	}
	/* Append the new data to the buffer */
	assert(packet->buffer != NULL);
	memcpy(packet->buffer + packet->received, ptr, size * nmemb);
	packet->received += size * nmemb;
	if (packet->received == packet->total_length) {
		/* Packet is received completely */
		acme_srv_response = malloc(packet->total_length + 1);
		memcpy(acme_srv_response, packet->buffer, packet->total_length);
		acme_srv_response[packet->total_length] = '\0';

		free(packet->buffer);
		packet->buffer = NULL;
		packet->received = 0;
		packet->total_length = 0;
	}

	return size * nmemb;
}

int8_t acme_new_acc(struct acme_account *client, struct acme_server *server)
{
	DEBUG("Requesting account.\n");
	/* if no nonce is available, request a new one */
	if (acme_nonce == NULL) {
		if (acme_new_nonce(server)) {
			return -1;
		}
	}

	/* Get the key primitive values */
	uint8_t *x_bin;
	uint8_t *y_bin;
	crypt_get_xy(client->key, &x_bin, &y_bin);

	char x_str[44];
	char y_str[44];
	base64url(x_bin, x_str, 32, sizeof(x_str));
	base64url(y_bin, y_str, 32, sizeof(y_str));

	free(x_bin);
	free(y_bin);

	/* Header */
	struct acme_header hdr;
	hdr.alg = "ES256";
	cJSON *jwk = cJSON_CreateObject();
	cJSON *kty = cJSON_CreateString("EC");
	cJSON *crv = cJSON_CreateString("P-256");
	cJSON *x = cJSON_CreateString(x_str);
	cJSON *y = cJSON_CreateString(y_str);

	/* The order of the elements is alphabetical,
         * so the print function outputs them correctly 
         * for the SHA256 hash function */
	/* We assume that cJSON prints the elements in
         * the order they were added, which is arguably
         * not that good */
	cJSON_AddItemToObject(jwk, "crv", crv);
	cJSON_AddItemToObject(jwk, "kty", kty);
	cJSON_AddItemToObject(jwk, "x", x);
	cJSON_AddItemToObject(jwk, "y", y);
	hdr.jwk = cJSON_Print(jwk);
	hdr.nonce = acme_nonce;
	hdr.url = server->resources[ACME_RES_NEW_ACC];
	hdr.kid = NULL;

	/* strip whitespace from JSON printout */
	char *stripped_jwk = malloc(strlen(hdr.jwk));
	uint16_t j = 0;
	for (uint16_t i = 0; i < strlen(hdr.jwk); i++) {
		if (hdr.jwk[i] != ' ' && hdr.jwk[i] != '\n' &&
		    hdr.jwk[i] != '\t') {
			stripped_jwk[j++] = hdr.jwk[i];
		}
	}
	stripped_jwk[j] = '\0';
	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256((uint8_t *)stripped_jwk, strlen(stripped_jwk), hash);
	char hash_str[SHA256_DIGEST_LENGTH * 2];
	base64url(hash, hash_str, SHA256_DIGEST_LENGTH, sizeof(hash_str));
	free(stripped_jwk);

	/* The key thumprint is used later to reply to challenges */
	acme_thumbprint = realloc(acme_thumbprint, strlen(hash_str) + 1);
	strcpy(acme_thumbprint, hash_str);
	cJSON_Delete(jwk);

	/* Assemble the JWT */
	char *header = acme_write_header(&hdr);
	char payload[] = "{\"termsOfServiceAgreed\":true}";
	char *token = crypt_mktoken(client->key, header, payload);

	/* Make the HTTP POST request */
	curl_post(server->resources[ACME_RES_NEW_ACC], token, acme_write_cb,
		  acme_header_cb, NULL, server->ca_cert);

	free(token);
	free(hdr.jwk);

	/* Wait for response */
	//TODO timeout
	while (acme_srv_response == NULL)
		;

	/* Parse the response */
	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	if (srv_resp == NULL) {
		const char *err = cJSON_GetErrorPtr();
		if (err != NULL) {
			ERROR("JSON parse error in server response: err\n");
		}
		return -1;
	}
	cJSON *status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status");
	cJSON *orders = cJSON_GetObjectItemCaseSensitive(srv_resp, "orders");
	if (cJSON_IsString(status)) {
		if (strcmp(status->valuestring, "valid")) {
			ERROR("Server response: status = %s\n",
			      status->valuestring);
			return -1;
		}
		acme_kid = malloc(strlen(acme_location) + 1);
		strcpy(acme_kid, acme_location);
		if (verbose) {
			ERROR("Account %s is valid\n", acme_kid);
		}
		client->status = ACME_STATUS_VALID;
		if (cJSON_IsString(orders)) {
			client->order_list =
				malloc(strlen(orders->valuestring) + 1);
			strcpy(client->order_list, orders->valuestring);
		}
	} else {
		DEBUG("Account is not valid.\n");

		/* The cause may be an incorrent nonce, so get a new 
                 * one just in case that fixes it */
		if (acme_nonce) {
			free(acme_nonce);
			acme_nonce = NULL;
			acme_new_nonce(server);
		}

		acme_print_srv_response(srv_resp);
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

void acme_print_srv_response()
{
	assert(acme_srv_response != NULL);
	NOTICE("Server response:\n%s\n", acme_srv_response);
}

cJSON *acme_parse_srv_resp()
{
	assert(acme_srv_response != NULL);
	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	free(acme_srv_response);
	acme_srv_response = NULL;
	return srv_resp;
}

int8_t acme_new_order(struct acme_account *client, struct acme_server *server,
		      struct string_node *domain_list)
{
	DEBUG("Updating order at: %s\n", server->resources[ACME_RES_NEW_ORDER]);

	/* Header */
	struct acme_header hdr;
	hdr.alg = "ES256";
	hdr.kid = acme_kid;
	hdr.nonce = acme_nonce;
	hdr.url = server->resources[ACME_RES_NEW_ORDER];

	/* Payload */
	cJSON *id;
	cJSON *ids = cJSON_CreateArray();
	cJSON *identifiers = cJSON_CreateObject();

	char domain[ACME_MAX_DOMAIN_LENGTH] = { 0 };
	assert(domain_list != NULL);
	struct string_node *domains = string_list_copy(domain_list);
	while (domains != NULL) {
		domains = string_list_pop_back(domains, domain, sizeof(domain));
		id = cJSON_CreateObject();
		cJSON_AddItemToObject(id, "type", cJSON_CreateString("dns"));
		cJSON_AddItemToObject(id, "value", cJSON_CreateString(domain));
		cJSON_AddItemToArray(ids, id);
	}
	cJSON_AddItemToObject(identifiers, "identifiers", ids);

	/* Assemble the JWT */
	char *header = acme_write_header(&hdr);
	char *payload = cJSON_Print(identifiers);
	char *token = crypt_mktoken(client->key, header, payload);

	cJSON_Delete(identifiers);
	free(payload);

	/* Make the HTTP POST request */
	curl_post(server->resources[ACME_RES_NEW_ORDER], token, acme_write_cb,
		  acme_header_cb, NULL, server->ca_cert);

	free(token);

	/* Wait for response */
	//TODO timeout
	while (acme_srv_response == NULL)
		;

	/* Create an order object from the server response */
	client->order = malloc(sizeof(struct acme_order));
	client->order->status = ACME_STATUS_UNKNOWN;
	client->order->identifiers = NULL;
	client->order->authz = NULL;
	client->order->finalize_url = NULL;
	client->order->cert_url = NULL;

	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	if (srv_resp == NULL) {
		const char *err = cJSON_GetErrorPtr();
		if (err != NULL) {
			ERROR("JSON parse error in server response: %s\n", err);
		}
		return -1;
	}
	cJSON *status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status");
	cJSON *srv_ids =
		cJSON_GetObjectItemCaseSensitive(srv_resp, "identifiers");
	cJSON *finalize =
		cJSON_GetObjectItemCaseSensitive(srv_resp, "finalize");
	cJSON *authz =
		cJSON_GetObjectItemCaseSensitive(srv_resp, "authorizations");
	if (cJSON_IsString(status)) {
		client->order->status = acme_get_status(status->valuestring);
	}

	cJSON *auth;
	cJSON_ArrayForEach(auth, authz)
	{
		if (cJSON_IsString(auth)) {
			client->order->authz = string_list_append(
				client->order->authz, auth->valuestring);
		} else {
			ERROR("Auth parse error\n");
		}
	}
	cJSON *srv_id;
	cJSON_ArrayForEach(srv_id, srv_ids)
	{
		cJSON *type = cJSON_GetObjectItemCaseSensitive(srv_id, "type");
		cJSON *value =
			cJSON_GetObjectItemCaseSensitive(srv_id, "value");
		if (cJSON_IsString(type) && cJSON_IsString(value)) {
			struct acme_identifier *new_id =
				malloc(sizeof(struct acme_identifier));
			new_id->value = malloc(strlen(value->valuestring) + 1);
			strcpy(new_id->value, value->valuestring);
			new_id->type = ACME_ID_DNS;
			client->order->identifiers = id_list_append(
				client->order->identifiers, new_id);
			free(new_id->value);
			free(new_id);
		} else {
			ERROR("Identifier parse error\n");
		}
	}

	if (cJSON_IsString(finalize)) {
		client->order->finalize_url =
			malloc(strlen(finalize->valuestring) + 1);
		strcpy(client->order->finalize_url, finalize->valuestring);
	} else {
		ERROR("Server response parse error\n");
		acme_print_srv_response();
		cJSON_Delete(srv_resp);
		free(acme_srv_response);
		acme_srv_response = NULL;
		return -1;
	}
	if (client->order->status == ACME_STATUS_PENDING) {
		DEBUG("Order %s updated successfully.\n", acme_location);
	}
	client->order->order_url = malloc(strlen(acme_location) + 1);
	strcpy(client->order->order_url, acme_location);
	cJSON_Delete(srv_resp);
	free(acme_srv_response);
	acme_srv_response = NULL;
	return 0;
}

int8_t acme_get_auth(struct acme_account *client, struct acme_server *server)
{
	/* Request authorization object from the server,
         * this function should be called as long as there are
         * elements in client->order->authz
         */

	/* Indicates whether at least one authorization from 
         * the list still needs to be checked, i.e. has status 
         * different from "valid". */
	uint8_t need_chal = 0;

	/* copy list to not mess with the original */
	struct string_node *authz = string_list_copy(client->order->authz);

	/* Delete the old authorization objects */
	authz_list_delete(client->authz_list);
	client->authz_list = NULL;

	while (authz != NULL) {
		/* Header */
		struct acme_header hdr;
		hdr.alg = "ES256";
		hdr.kid = acme_kid;
		hdr.nonce = acme_nonce;

		char url[512]; //TODO malloc
		hdr.url = url;
		authz = string_list_pop_back(authz, url, sizeof(url));

		/* Assemble JWT */
		char *header = acme_write_header(&hdr);
		char payload[] = "";
		char *token = crypt_mktoken(client->key, header, payload);

		/* Make the HTTP POST request */
		curl_post(url, token, acme_write_cb, acme_header_cb, NULL,
			  server->ca_cert);

		free(token);

		/* Wait for response */
		//TODO timeout
		while (acme_srv_response == NULL)
			;

		/* Parse the response */
		cJSON *srv_resp = cJSON_Parse(acme_srv_response);
		if (srv_resp == NULL) {
			const char *err = cJSON_GetErrorPtr();
			if (err != NULL) {
				ERROR("JSON parse error"
				      "in server response: %s\n",
				      err);
			}
			free(acme_srv_response);
			acme_srv_response = NULL;
			return -1;
		}

		/* The authorization object will contain the domain it is for 
                 * (we don't know if we requested multiple domains) and the 
                 * challenges 
                 */

		struct acme_auth *new_auth = malloc(sizeof(struct acme_auth));
		struct acme_identifier *new_id =
			malloc(sizeof(struct acme_identifier));
		new_auth->challenges = NULL;
		new_id->type = ACME_ID_DNS;
		new_id->value = NULL;
		new_auth->id = new_id;
		new_auth->status = ACME_STATUS_UNKNOWN;

		cJSON *challenges = cJSON_GetObjectItemCaseSensitive(
			srv_resp, "challenges");
		cJSON *identifier = cJSON_GetObjectItemCaseSensitive(
			srv_resp, "identifier");
		cJSON *id_value =
			cJSON_GetObjectItemCaseSensitive(identifier, "value");
		cJSON *status =
			cJSON_GetObjectItemCaseSensitive(srv_resp, "status");

		if (!cJSON_IsString(status)) {
			ERROR("Error while checking authorization "
			      "state:\n%s\n",
			      acme_srv_response);
			free(acme_srv_response);
			acme_srv_response = NULL;
			cJSON_Delete(srv_resp);
			acme_free_auth(new_auth);
			return -1;
		} else if (acme_get_status(status->valuestring) ==
			   ACME_STATUS_VALID) {
			DEBUG("Authorization for \"%s\" is valid, no more challenges"
			      " need to be fulfilled.\n",
			      id_value->valuestring);

			acme_free_auth(new_auth);
		} else if (acme_get_status(status->valuestring) ==
			   ACME_STATUS_PENDING) {
			DEBUG("Authorization is pending.\n");
			need_chal = 1;
			new_id->type = ACME_ID_DNS;
			if (cJSON_IsString(id_value)) {
				new_id->value = malloc(
					strlen(id_value->valuestring) + 1);
				strcpy(new_id->value, id_value->valuestring);
			}

			/* For a single authorization (for a single identifier aka domain),
                         * there are probably multiple challenges we can choose from. If 
                         * we fulfill one, we should be authorized. 
                         */
			cJSON *chal;
			cJSON_ArrayForEach(chal, challenges)
			{
				cJSON *type = cJSON_GetObjectItemCaseSensitive(
					chal, "type");
				cJSON *url = cJSON_GetObjectItemCaseSensitive(
					chal, "url");
				cJSON *token = cJSON_GetObjectItemCaseSensitive(
					chal, "token");
				cJSON *status =
					cJSON_GetObjectItemCaseSensitive(
						chal, "status");

				struct acme_chal *new_chal =
					malloc(sizeof(struct acme_chal));

				new_chal->type = ACME_CHAL_DNS01;
				new_chal->status = ACME_STATUS_UNKNOWN;
				if (cJSON_IsString(status)) {
					new_chal->status = acme_get_status(
						status->valuestring);
				} else {
					ERROR("Challenge has invalid status.\n");
					free(new_chal);
					chal_list_delete(new_auth->challenges);
					acme_free_auth(new_auth);
					return -1;
				}

				new_chal->token =
					malloc(strlen(token->valuestring) + 1);
				strcpy(new_chal->token, token->valuestring);

				if (!(strcmp(type->valuestring, "http-01"))) {
					new_chal->type = ACME_CHAL_HTTP01;
				}
				if (!(strcmp(type->valuestring, "dns-01"))) {
					new_chal->type = ACME_CHAL_DNS01;
				}
				new_chal->url =
					malloc(strlen(url->valuestring) + 1);
				strcpy(new_chal->url, url->valuestring);
				new_auth->challenges = chal_list_append(
					new_auth->challenges, new_chal);
				free(new_chal->token);
				free(new_chal->url);
				free(new_chal);
			}

			if (new_auth->status == ACME_STATUS_INVALID) {
				ERROR("Authorization has invalid status.\n");
				acme_free_auth(new_auth);
				return -1;
			}
			DEBUG("Parsed authorization object for \"%s\".\n",
			      new_auth->id->value);
			client->authz_list =
				authz_list_append(client->authz_list, new_auth);
			chal_list_delete(new_auth->challenges);
			new_auth->challenges = NULL;
			free(new_auth->id->value);
			free(new_auth->id);
			free(new_auth);
			free(acme_srv_response);
			acme_srv_response = NULL;
		} else if (acme_get_status(status->valuestring) ==
			   ACME_STATUS_INVALID) {
			ERROR("Authorization is invalid: "
			      "The server could not verify the "
			      "challenges. Check domain name and "
			      "firewall rules and try again.\n");
			acme_free_auth(new_auth);
			free(acme_srv_response);
			acme_srv_response = NULL;
			return -1;
		}
		if (acme_srv_response) {
			free(acme_srv_response);
			acme_srv_response = NULL;
		}
		cJSON_Delete(srv_resp);
	}
	if (need_chal) {
		return 0;
	}
	return 1;
}

char *acme_get_token(char *url)
{
	char *token = malloc(256);
	strcpy(token, url + strlen("/.well-known/acme-challenge/"));
	strcpy(token + strlen(token), ".");
	strcpy(token + strlen(token), acme_thumbprint);
	return token;
}

int8_t acme_authorize(struct acme_account *client, struct acme_server *server,
		      enum acme_chal_type method)
{
	/* Take the an authorization objects and tell the server
         * that we are ready for challenge validation */

	struct acme_auth *auth = malloc(sizeof(struct acme_auth));
	auth->challenges = NULL;
	auth->wildcard = 0;
	auth->id = malloc(sizeof(struct acme_identifier));
	auth->id->type = ACME_ID_DNS;
	auth->id->value = NULL;
	auth->status = ACME_STATUS_UNKNOWN;
	while (client->authz_list != NULL) {
		client->authz_list =
			authz_list_pop_back(client->authz_list, auth);
		struct acme_chal *chal = malloc(sizeof(struct acme_chal));
		chal->type = ACME_CHAL_HTTP01;
		chal->token = NULL;
		chal->status = ACME_STATUS_UNKNOWN;
		chal->url = NULL;

		/* Auth object must contain at least 
                 * one challenge to continue */
		if (auth->challenges == NULL) {
			acme_free_auth(auth);
			return -1;
		}

		while (auth->challenges != NULL) {
			auth->challenges =
				chal_list_pop_back(auth->challenges, chal);
			if (chal->type == method) {
				break;
			}
			free(chal->token);
			free(chal->url);
		}
		acme_free_auth(auth);
		if (chal->type != method) {
			ERROR("Can not authorize: server did "
			      "not offer a challenge of type of "
			      "requested type.");
			return -1;
		}

		chal->status = ACME_STATUS_UNKNOWN;

		/* Header */
		struct acme_header hdr;
		hdr.alg = "ES256";
		hdr.kid = acme_kid;
		hdr.nonce = acme_nonce;
		hdr.url = chal->url;

		/* Assemble the JWT */
		char *header = acme_write_header(&hdr);
		char payload[] = "{}";
		char *token = crypt_mktoken(client->key, header, payload);

		/* Make HTTP POST request */
		/* this indicates to the server that we are ready
                 * that the server tries to attempt the challenge 
                 * checking */
		curl_post(chal->url, token, acme_write_cb, acme_header_cb, NULL,
			  server->ca_cert);

		free(chal->token);
		free(chal->url);
		free(chal);
		free(token);

		/* Wait for response */
		//TODO timeout
		while (acme_srv_response == NULL)
			;

		cJSON *srv_resp = cJSON_Parse(acme_srv_response);
		if (srv_resp == NULL) {
			const char *err = cJSON_GetErrorPtr();
			if (err != NULL) {
				ERROR("JSON parse error in server response: err\n");
			}
			return -1;
		}
		free(acme_srv_response);
		acme_srv_response = NULL;
		cJSON_Delete(srv_resp);
	}
	return 0;
}
int8_t acme_finalize(struct acme_account *client, struct acme_server *server,
		     struct string_node *domain_list)
{
	struct acme_header hdr;
	hdr.alg = "ES256";
	hdr.kid = acme_kid;
	hdr.nonce = acme_nonce;
	hdr.url = client->order->finalize_url;

	char *header = acme_write_header(&hdr);

	EVP_PKEY *csr_key = NULL;
	X509_REQ *csr;
	char csr_pem[4096] = { 0 };
	crypt_new_csr(&csr_key, &csr, csr_pem, sizeof(csr_pem), domain_list);
	crypt_strip_csr(csr_pem);
	b64_normal2url(csr_pem);

	/* Set certificate key to 0600 permissions */
	umask(~(S_IRUSR | S_IWUSR));
	FILE *keyfile;
	keyfile = fopen("client.key", "w");
	PEM_write_PKCS8PrivateKey(keyfile, csr_key, NULL, NULL, 0, 0, "");
	fclose(keyfile);
	EVP_PKEY_free(csr_key);

	char payload[4096];
	strcpy(payload, "{\"csr\":\"");
	strcpy(payload + strlen(payload), csr_pem);
	strcpy(payload + strlen(payload), "\"}");

	char *token = crypt_mktoken(client->key, header, payload);

	curl_post(client->order->finalize_url, token, acme_write_cb,
		  acme_header_cb, NULL, server->ca_cert);

	free(token);
	X509_REQ_free(csr);

	/* Wait for response */
	//TODO timeout
	while (acme_srv_response == NULL)
		;

	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	free(acme_srv_response);
	acme_srv_response = NULL;

	cJSON *status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status");
	if (!cJSON_IsString(status)) {
		cJSON_Delete(srv_resp);
		return -1;
	}

	int ret = 0;
	switch (acme_get_status(status->valuestring)) {
	case ACME_STATUS_PROCESSING:
		DEBUG("Server is processing certificate request.\n");
		ret = 0;
		break;
	case ACME_STATUS_VALID:
		DEBUG("Server has issued certificate.\n");
		ret = 1;
		break;
	default:
		ret = -1;
	}

	cJSON_Delete(srv_resp);

	return ret;
}
int8_t acme_get_order_status(struct acme_account *client,
			     struct acme_server *server)
{
	struct acme_header hdr;
	hdr.alg = "ES256";
	hdr.kid = acme_kid;
	hdr.nonce = acme_nonce;
	hdr.url = client->order->order_url;

	char *header = acme_write_header(&hdr);
	char payload[] = "";
	char *token = crypt_mktoken(client->key, header, payload);

	curl_post(client->order->order_url, token, acme_write_cb,
		  acme_header_cb, NULL, server->ca_cert);

	free(token);

	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	cJSON *status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status");
	cJSON *certificate =
		cJSON_GetObjectItemCaseSensitive(srv_resp, "certificate");

	free(acme_srv_response);
	acme_srv_response = NULL;

	if (acme_get_status(status->valuestring) == ACME_STATUS_VALID) {
		if (cJSON_IsString(certificate)) {
			if (client->order->cert_url != NULL) {
				free(client->order->cert_url);
			}
			client->order->cert_url =
				malloc(strlen(certificate->valuestring) + 1);
			strcpy(client->order->cert_url,
			       certificate->valuestring);
		}
		cJSON_Delete(srv_resp);
		return 1;
	}
	cJSON_Delete(srv_resp);
	return 0;
}

int8_t acme_get_cert(struct acme_account *client, struct acme_server *server)
{
	/* Header */
	struct acme_header hdr;
	hdr.alg = "ES256";
	hdr.kid = acme_kid;
	hdr.nonce = acme_nonce;
	hdr.url = client->order->cert_url;

	/* Assemble JWT */
	char *header = acme_write_header(&hdr);
	char payload[] = "";
	char *token = crypt_mktoken(client->key, header, payload);

	/* Make HTTP POST request */
	char *headers = "Accept: application/pem-certificate-chain";
	curl_post(client->order->cert_url, token, acme_write_cb, acme_header_cb,
		  headers, server->ca_cert);

	free(token);

	/* We expect a PEM certificate chain here, so normally
         * this parse would fail. If e.g. the nonce is rejected,
         * this error will be detected here. */
	cJSON *srv_resp = cJSON_Parse(acme_srv_response);
	cJSON *status = cJSON_GetObjectItemCaseSensitive(srv_resp, "status");

	if (status != NULL) {
		cJSON_Delete(srv_resp);
		return -1;
	}
	cJSON_Delete(srv_resp);
	return 0;
}

int8_t acme_new_nonce(struct acme_server *server)
{
	curl_get(server->resources[ACME_RES_NEW_NONCE], acme_header_cb, NULL,
		 server->ca_cert);
	return 0;
}

int8_t acme_get_resources(struct acme_server *server, uint8_t accept_tos)
{
	/* Resources can be fetched with GET, no POST-as-GET needed */
	curl_get(server->resources[ACME_RES_DIR], acme_header_cb, acme_write_cb,
		 server->ca_cert);

	/* Wait for response */
	//TODO timeout
	while (acme_srv_response == NULL)
		;

	cJSON *res = cJSON_Parse(acme_srv_response);
	if (res == NULL) {
		ERROR("JSON parse error.\n");
		return -1;
	}
	cJSON *nonce = cJSON_GetObjectItemCaseSensitive(res, "newNonce");
	cJSON *acc = cJSON_GetObjectItemCaseSensitive(res, "newAccount");
	cJSON *order = cJSON_GetObjectItemCaseSensitive(res, "newOrder");
	cJSON *revoke = cJSON_GetObjectItemCaseSensitive(res, "revokeCert");
	cJSON *meta = cJSON_GetObjectItemCaseSensitive(res, "meta");
	cJSON *terms = cJSON_GetObjectItemCaseSensitive(meta, "termsOfService");

	if (cJSON_IsString(terms)) {
		NOTICE("Terms of service are located at %s\n",
		       terms->valuestring);
		if (!accept_tos) {
			NOTICE("Do you agree to the terms of service? [Y/n]");
			char answer;
			int len = scanf("%c", &answer);
			if (len == 1 && answer != 'y' && answer != 'Y' &&
			    answer != 0x0A) {
				ERROR("You must agree to the terms of service"
				      " in order to continue.\n");
				return -2;
			}
		} else {
			DEBUG("Accepting terms of service.\n");
		}
	}

	// TODO NULL checks
	acme_server_add_resource(server, ACME_RES_NEW_NONCE,
				 nonce->valuestring);
	acme_server_add_resource(server, ACME_RES_NEW_ACC, acc->valuestring);
	acme_server_add_resource(server, ACME_RES_NEW_ORDER,
				 order->valuestring);
	acme_server_add_resource(server, ACME_RES_REVOKE_CERT,
				 revoke->valuestring);

	DEBUG("Added server resources:\n");
	DEBUG("NEW_NONCE: %s\n", nonce->valuestring);
	DEBUG("NEW_ACC: %s\n", acc->valuestring);
	DEBUG("NEW_ORDER: %s\n", order->valuestring);
	DEBUG("NEW_REVOKE_CERT: %s\n", revoke->valuestring);

	if (res != NULL)
		cJSON_Delete(res);

	if (acme_srv_response) {
		free(acme_srv_response);
		acme_srv_response = NULL;
	}
	return 0;
}

char *acme_write_header(struct acme_header *header)
{
	char *out;

	/* get length of header fields */
	uint16_t len;
	if (header->kid == NULL) {
		len = strlen(header->alg) + strlen(header->jwk) +
		      strlen(header->nonce) + strlen(header->url);
	} else {
		len = strlen(header->alg) + strlen(header->kid) +
		      strlen(header->nonce) + strlen(header->url);
	}
	/* add constant length of labels
         * note that the longer variant (kid) */
	len += strlen("{\"alg\":\"\","
		      "\"kid\":\"\","
		      "\"nonce\":\"\","
		      "\"url\":\"\"}");
	out = malloc(len + 1); // +1 for null termination

	/* kid and jwt field are mutually exclusive. */
	if (header->kid == NULL) {
		sprintf(out,
			"{\"alg\":\"%s\","
			"\"jwk\":%s,"
			"\"nonce\":\"%s\","
			"\"url\":\"%s\"}",
			header->alg, header->jwk, header->nonce, header->url);
	} else {
		sprintf(out,
			"{\"alg\":\"%s\","
			"\"kid\":\"%s\","
			"\"nonce\":\"%s\","
			"\"url\":\"%s\"}",
			header->alg, header->kid, header->nonce, header->url);
	}
	return out;
}

void acme_cleanup(struct acme_account *client)
{
	free(acme_kid);
	free(acme_location);
	free(acme_thumbprint);
	if (acme_nonce != NULL) {
		free(acme_nonce);
	}
	string_list_delete(client->order->authz);
	id_list_delete(client->order->identifiers);
	authz_list_delete(client->authz_list);
	free(client->order_list);
	free(client->order->cert_url);
	free(client->order->finalize_url);
	free(client->order->order_url);
}

void acme_free_auth(struct acme_auth *auth)
{
	free(auth->id->value);
	free(auth->id);
	chal_list_delete(auth->challenges);
	free(auth);
}
