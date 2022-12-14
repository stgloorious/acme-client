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
#include "http.h"
#include "acme.h"
#include "b64.h"
#include "crypt.h"
#include "err.h"

/* Global indicator whether in verbose mode */
uint8_t verbose = 0;

/* Global indicator whether we received a keyboard interrupt */
volatile sig_atomic_t int_shutdown = 0;

static void int_handler(int dummy)
{
	int_shutdown = (dummy > 0);
}

int main(int argc, char **argv)
{
	signal(SIGINT, int_handler); //register keyboard interrupt handler

	/* Parse command-line arguments */
	struct arguments arguments;
	arguments.dir_url = "https://acme-v02.api.letsencrypt.org/directory";
	arguments.domain_list = NULL;
	arguments.ndomain = 0;
	arguments.port = "80";
	arguments.server_cert = NULL;
	arguments.account_key = NULL;
	arguments.verbose = 0;
	arguments.tos_agree = 0;

	if (argp_parse(&argp, argc, argv, 0, 0, &arguments)) {
		ERROR("Error parsing command-line arguments.\n");
		return EINVAL;
	}
	verbose = arguments.verbose;
	DEBUG("Using OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

	/* An account represents the client */
	struct acme_account client;
	EVP_PKEY *key = NULL;

	if (arguments.account_key) {
		if (crypt_read_key(&key, arguments.account_key)) {
			return -1;
		}
	} else {
		char keyfile[] = "account.pem";
		NOTICE("No account key provided, creating a new one at \"%s\"\n",
		       keyfile);
		if (crypt_new_key(&key)) {
			return -1;
		}
		if (crypt_write_key(key, keyfile)) {
			return -1;
		}
	}
	client.key = &key;
	client.order = NULL;
	client.order_list = NULL;
	client.status = ACME_STATUS_UNKNOWN;
	client.authz_list = NULL;

	/* The only information we have about the ACME server is the dir 
         * resource. The other resource urls are obtained by sending a 
         * request to this dir resource 
         */
	struct acme_server *server = acme_server_new();
	acme_server_add_resource(server, ACME_RES_DIR, arguments.dir_url);
	if (acme_server_add_cert(server, arguments.server_cert) != 0) {
		goto fail;
	}
	if (acme_get_resources(server, arguments.tos_agree) != 0) {
		ERROR("Could not obtain ACME resource URLs.\n");
		goto fail;
	}

	/* Request a new account, which is identified by our key */
	uint8_t retry_count = 0;
	while (acme_new_acc(&client, server)) {
		ERROR("Could not create account.\n");
		if (retry_count < 3) {
			retry_count++;
		} else {
			goto fail;
		}
		sleep(2);
	}

	enum acme_chal_type method = ACME_CHAL_HTTP01;

	/* run state machine that places order */
	int8_t ret = 0;
	while ((ret == 0) && !int_shutdown) {
		ret = acme_fsm_order(&client, server, arguments.domain_list);
	}
	/* FSM returns 2 if all authorization are already validated */
	if (ret == 1) {
		//TODO add manual validation
		NOTICE("Performing automatic validation\n");

		/* Start HTTP server used to validate challenges */
		pthread_t http_chal_thr;
		void *http_chal_thr_result;
		struct http_chal_args cargs = { atoi(arguments.port),
						"0.0.0.0" };
		pthread_create(&http_chal_thr, NULL, http_chal_server, &cargs);
		DEBUG("HTTP challenge server started on port %i\n", cargs.port);

		/* At this point the challenges should be ready for the server
                 * to be seen */
		ret = 0;
		while (ret == 0 && !int_shutdown) {
			ret = acme_fsm_validate(&client, server, method);
		}
		if (ret == -1) {
			int_shutdown = 1;
			sleep(2);
			pthread_join(http_chal_thr, &http_chal_thr_result);
			goto fail;
		}

		/* All challenges are validated at this point */

		/* Shutdown HTTP server*/
		int_shutdown = 1;
		pthread_join(http_chal_thr, &http_chal_thr_result);
		int_shutdown = 0;
	}
	NOTICE("All domains were successfully verified.\n");

	ret = 0;
	while (ret == 0 && !int_shutdown) {
		ret = acme_fsm_cert(&client, server, arguments.domain_list);
	}
	goto success;
fail:
	string_list_delete(arguments.domain_list);
	acme_server_delete(server);
	acme_cleanup(&client);
	free(client.order);
	EVP_PKEY_free(key);
	return -1;
success:
	string_list_delete(arguments.domain_list);
	acme_server_delete(server);
	acme_cleanup(&client);
	free(client.order);
	EVP_PKEY_free(key);
	return 0;
}
