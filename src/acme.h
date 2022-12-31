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

/* JSON Web Key */
struct acme_jwk {
	char *kty;
	char *crv;
	char *x;
	char *y;
};

struct acme_header {
	char *alg;
	struct acme_jwk _jwk;
	char *jwk;
	char *kid;
	char *nonce;
	char *url;
};

struct acme_server {
	char **resources; // Array of resource URLs, uses acme_rsrc as index
	char *ca_cert; // CA certificate used to sign the server's HTTPS cert

	// TODO implement
	char *nonce; // nonce included in every HTTP POST
};

/* ACME resource urls */
enum acme_rsrc {
	ACME_RES_DIR,
	ACME_RES_KEYCHANGE,
	ACME_RES_NEW_ACC,
	ACME_RES_NEW_NONCE,
	ACME_RES_NEW_ORDER,
	ACME_RES_NEW_AUTHZ,
	ACME_RES_REVOKE_CERT,
	ACME_RES_ORDER_LIST,
	ACME_NUMBER_OF_RES
}; // This must always be the last entry

enum acme_status {
	ACME_STATUS_UNKNOWN,
	ACME_STATUS_VALID,
	ACME_STATUS_PENDING,
	ACME_STATUS_READY,
	ACME_STATUS_PROCESSING,
	ACME_STATUS_INVALID
};

/* this represents and identifies the client */
struct acme_account {
	enum acme_status status;
	EVP_PKEY **key;
	char *order_list;
	struct acme_order *order;
	struct authz_node *authz_list;
};

/* The identifier type is always dns,
 * the value is the url the url we want on the cert.
 * Not to be confused with the challenge type,
 * which can either be http-01 or dns-01 */
enum acme_id_type { ACME_ID_DNS };
struct acme_identifier {
	enum acme_id_type type;
	char *value;
};

/* Order object represents client's request for
 * a certificate */
struct acme_order {
	enum acme_status status;
	struct id_node *identifiers; // list of @acme_identifier

	/* for pending orders, the authorizations the client
         * needs to complete. There may not be a 1:1 relationship
         * between authorizations and identifiers.
         * A request to this url reveals the corresponding 
         * authz object, which is done by calling 
         * acme_get_auth(). The authz objects are at 
         * client->authz. */
	struct string_node *authz;
	char *order_url;
	char *finalize_url;
	char *cert_url; // download cert from here
};

/* authorization objects represent a server's authorization
 * for an account to represent an identifier */
struct acme_auth {
	enum acme_status status;
	struct acme_identifier *id;
	struct chal_node *challenges;
	uint8_t wildcard;
};

/* challenge objects represent and specify the way
 * a client can prove ownership of an identifier
 */
enum acme_chal_type { ACME_CHAL_HTTP01, ACME_CHAL_DNS01 };
struct acme_chal {
	enum acme_chal_type type;
	char *url;
	enum acme_status status;
	char *token;
};

#define ACME_MAX_NONCE_LENGTH 64
#define ACME_MAX_DOMAIN_LENGTH 128

void acme_print_jwk();

struct acme_server *acme_server_new();

int8_t acme_server_delete(struct acme_server *server);

int8_t acme_server_add_resource(struct acme_server *server,
				enum acme_rsrc resource, char *url);
int8_t acme_server_add_cert(struct acme_server *server, char *ca_cert);

struct acme_order *acme_order_new();

/**
 * Place an order on an already existing account 
 * for the domains given. Authorizations including 
 * all challenges will be obtained and stored in client.
 * This is used for both manual and automatic validation.
 *
 * @param[inout] client
 * @param[in] server
 * @param[in] domain_list
 * @returns 0 on normal operation, -1 on error and 1 on completion.
 */
int8_t acme_fsm_order(struct acme_account *client, struct acme_server *server,
		      struct string_node *domain_list);

/**
 * performs automatic validation for the challenges obtained 
 * previously.
 *
 * @param[inout] client
 * @param[in] server
 * @param[in] method
 */
int8_t acme_fsm_validate(struct acme_account *client,
			 struct acme_server *server,
			 enum acme_chal_type method);

/* After successful authorization, request the issuance 
 * of the certificate and download and save it. 
 */
int8_t acme_fsm_cert(struct acme_account *client, struct acme_server *server,
		     struct string_node *domain_list);

/* Uses the key in the client object to request a new account in the 
 * server's database. It does not matter if an account already exists.
 *
 * @param[in] client
 * @param[in] server
 */
int8_t acme_new_acc(struct acme_account *client, struct acme_server *server);

/* Request a new order for the domains given
 * @param[inout] client
 * @param[in] server
 * @param[in] domain_list
 */
int8_t acme_new_order(struct acme_account *client, struct acme_server *server,
		      struct string_node *domain_list);

/**
 * Ask the server for authorization objects for the given
 * identifiers given in client->order->identifiers. 
 * The objects will be stored in client->authz.
 *
 * @param[in] client
 * @param[in] server
 * @returns 0 if there are pending authz, 1 if all authz are valid, -1 on error
 */
int8_t acme_get_auth(struct acme_account *client, struct acme_server *server);

int8_t acme_check_auth(struct acme_account *client, struct acme_server *server);

/**
 * Go through the authorizations list and fulfill a challenge each
 */
int8_t acme_authorize(struct acme_account *client, struct acme_server *server,
		      enum acme_chal_type method);

int8_t acme_add_root_cert(char *ca_cert, char *root_cert_url);

int8_t acme_list_orders(struct acme_account *client,
			struct acme_server *server);

int8_t acme_finalize(struct acme_account *client, struct acme_server *server,
		     struct string_node *domain_list);

/**
 * Get ACME resources from dir url and save it to @server, ask user for ToS
 * @param[in] server 
 * @param[in] accept_tos flag to indicate whether --accept-tos flag is given
 * @returns 0 on success, -1 on error, -2 if user did not agree to ToS
 */
int8_t acme_get_resources(struct acme_server *server, uint8_t accept_tos);

int8_t acme_get_order_status(struct acme_account *client,
			     struct acme_server *server);

int8_t acme_get_cert(struct acme_account *client, struct acme_server *server);

int8_t acme_revoke_cert(struct acme_account *client, struct acme_server *server,
			char *certfile);

int8_t acme_new_nonce(struct acme_server *server);

char *acme_write_header(struct acme_header *header);

void acme_write_payload(char *out, uint16_t len);

void acme_print_srv_response();

cJSON *acme_parse_srv_resp();

char *acme_get_token(char *url);

char *acme_get_token_dns();

void acme_cleanup(struct acme_account *client);

void acme_free_auth(struct acme_auth *auth);
