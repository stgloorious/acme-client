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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "string.h"
#include "crypt.h"
#include "b64.h"

extern uint8_t verbose;

void crypt_get_xy(EVP_PKEY **pkey, uint8_t **x, uint8_t **y)
{
	/* extract the public key from pkey which contains the 
         * x and y values */
	unsigned char *ppub;
	int l = EVP_PKEY_get1_encoded_public_key(*pkey, &ppub);
	assert(l == 65); // uncompressed format is always 65 bytes

	/* The first byte is a prefix:
         * 0x04: uncompressed format (both x and y, each 32 bits)
         * 0x02/3: compressed format (only x) */

	assert(*ppub == 0x04); //compressed format is not supported

	/* ...followed by 32 byte x-value and 32 byte y-value */
	*x = malloc(32);
	*y = malloc(32);
	memcpy(*x, ppub + 1, 32);
	memcpy(*y, ppub + 33, 32);
	free(ppub);
}

int8_t crypt_read_key(char *keyfile, EVP_PKEY **key)
{
	BIO *mem = BIO_new(BIO_s_mem());
	BIO_write(mem, keyfile, strlen(keyfile));
	assert(mem != NULL);

	EVP_PKEY_free(*key);
	*key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
	if (*key == NULL) {
		printf("Private key parsing error: must be in PEM format.\n");
		BIO_free(mem);
		return -1;
	}
	BIO_free(mem);
	return 0;
}

int8_t crypt_new_key(EVP_PKEY **key)
{
	*key = EVP_EC_gen("prime256v1");

	assert(*key != NULL);
	return 0;
}

int8_t crypt_sign(const char *msg, EVP_PKEY *key, char *signature,
		  uint16_t tlen)
{
	EVP_MD_CTX *ctx = NULL;
	ctx = EVP_MD_CTX_create();
	assert(ctx != NULL);

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1) {
		printf("Could not initalise signing context.\n");
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	if (EVP_DigestSignUpdate(ctx, msg, strlen(msg)) != 1) {
		printf("Could not update signing context.\n");
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	/* Call signing function with an empty destination first
         * to get the length */
	size_t der_slen;
	if (EVP_DigestSignFinal(ctx, NULL, &der_slen) != 1) {
		printf("Signing failed.\n");
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	/* Create the signature in DER format */
	uint8_t *der_sig = malloc(der_slen);
	assert(der_sig != NULL);
	if (EVP_DigestSignFinal(ctx, der_sig, &der_slen) != 1) {
		printf("Signing failed.\n");
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	EVP_MD_CTX_destroy(ctx);

	/* The signature needs to be converted to raw 
         * format to get R and S values. Final signature
         * is R || S */
	ECDSA_SIG *ec_sig;
	const BIGNUM *ec_sig_r = NULL;
	const BIGNUM *ec_sig_s = NULL;

	/* we need to copy this pointer so we can still
         * free it later, because d2i_ECDSA_SIG will overwrite it */
	void *der_sig_cp = der_sig;

	ec_sig = d2i_ECDSA_SIG(NULL, (const uint8_t **)&der_sig, der_slen);
	ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);

	/* R and S values are 32 byte, so we need 64 byte for 
         * hex representation + NULL terminator */
	char *r = BN_bn2hex(ec_sig_r);
	char *s = BN_bn2hex(ec_sig_s);

	//printf("R: %s\nS: %s\n", r, s);

	/* we only need the copied R and S values */
	ECDSA_SIG_free(ec_sig);
	free(der_sig_cp);

	/* concatenate values */
	char cat_sig[512] = { 0 };
	memcpy(cat_sig, r, 64);
	memcpy(cat_sig + 64, s, 64);
	cat_sig[128] = '\0';

	free(r);
	free(s);

	/* convert to binary */
	uint8_t cat_sig_b[512] = { 0 };
	//uint8_t* ptr = (uint8_t*)cat_sig;
	for (int i = 0; i <= 64; i++) {
		//char hex[2] = {*ptr, *(ptr+1)};
		static char hex[2] = { 0 };
		hex[0] = cat_sig[2 * i];
		hex[1] = cat_sig[2 * i + 1];
		//TODO fix
		//printf("%c%c", hex[0], hex[1]);
		cat_sig_b[i] = strtol(hex, NULL, 16);
		//ptr += 2;
	}

	assert(tlen > strlen(msg));
	strcpy(signature, msg);

	char sig[4096] = { 0 };
	base64url(cat_sig_b, sig, 64, sizeof(sig));

	//printf("Signature: %s\n", sig);

	sprintf(signature, "%s", sig);
	return 0;
}

int8_t crypt_new_csr(EVP_PKEY **key, X509_REQ **csr, char *csr_pem,
		     uint16_t len, struct string_node *domain_list)
{
	//TODO error handling
	if (verbose)
		printf("Generating new RSA key with 2048 bits.\n");
	*key = EVP_RSA_gen(2048);
	//crypt_print_key(*key);

	if (verbose)
		printf("Generating CSR.\n");
	*csr = X509_REQ_new();
	if (*csr == NULL) {
		printf("Could not generate CSR.\n");
	}
	if (X509_REQ_set_pubkey(*csr, *key) != 1) {
		printf("Could not set public key in CSR.\n");
	}

	struct string_node *domains = string_list_copy(domain_list);
	char domain[128];
	domains = string_list_pop_back(domains, domain, sizeof(domain));

	X509_NAME *name = NULL;
	name = X509_REQ_get_subject_name(*csr);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *)domain, -1, -1, 0);

	STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

	string_list_delete(domains);
	domains = string_list_copy(domain_list);
	char san[512] = { 0 };
	while (domains != NULL) {
		char domain[128];
		domains = string_list_pop_back(domains, domain, sizeof(domain));
		char alt_name[128] = { 0 };
		if (strlen(san) > 0) {
			strcpy(alt_name, ", DNS:");
		} else {
			strcpy(alt_name, "DNS:");
		}
		strcpy(alt_name + strlen(alt_name), domain);
		strcpy(san + strlen(san), alt_name);
	}
	X509_EXTENSION *ex =
		X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);

	sk_X509_EXTENSION_push(exts, ex);
	X509_REQ_add_extensions(*csr, exts);

	if (X509_REQ_sign(*csr, *key, EVP_sha256()) == 0) {
		printf("Could not sign CSR.\n");
	}

	BIO *buf = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(buf, *csr);
	BIO_read(buf, csr_pem, len);
	BIO_free(buf);
	X509_EXTENSION_free(ex);
	sk_X509_EXTENSION_free(exts);
	return 0;
}

int8_t crypt_strip_csr(char *csr_pem)
{
	char b64[4096];
	memcpy(b64, csr_pem + strlen("-----BEGIN CERTIFICATE REQUEST-----\n"),
	       strlen(csr_pem));
	char *end = strstr(b64, "-----END CERTIFICATE REQUEST-----\n");
	*(end) = '\0';

	char b64_[4096];
	int i = 0, j = 0;
	while (b64[i] != '\0') {
		if (b64[i] != '\n') {
			b64_[j++] = b64[i];
		}
		i++;
	}
	b64_[j] = '\0';
	strcpy(csr_pem, b64_);
	return 0;
}

char *crypt_mktoken(EVP_PKEY **key, char *header, char *payload)
{
	/* Base64-encode payload and header separately */
	uint16_t header_len = (strlen(header) + 1) * 1.5;
	char *header64 = malloc(header_len);
	base64url((uint8_t *)header, header64, strlen(header), header_len);
	free(header);

	uint16_t payload_len = (strlen(payload) + 1) * 1.5;
	char *payload64 = malloc(payload_len);
	base64url((uint8_t *)payload, payload64, strlen(payload), payload_len);

	/* The token that is signed consists of concatenated base64-encoded
         * header and payload, separated by '.' */
	char *token2sign = malloc(header_len + payload_len + 1);
	sprintf(token2sign, "%s.%s", header64, payload64);

	/* Sign the token */
	/* TODO check if signature size is always 64 bytes */
	uint16_t token_len = header_len + payload_len + 1 + 64;
	char *token = malloc(token_len);
	crypt_sign(token2sign, *key, token, token_len);
	free(token2sign);

	/* The token that is actually sent in HTTP POST body is 
         * a JSON that includes the base64-encoded values */
	uint16_t body_len = header_len + payload_len + token_len;
	body_len += strlen("{\"protected\":\"\","
			   "\"payload\":\"\","
			   "\"signature\":\"\"}");
	char *body = malloc(body_len);
	sprintf(body,
		"{\"protected\":\"%s\","
		"\"payload\":\"%s\","
		"\"signature\":\"%s\"}",
		header64, payload64, token);

	free(header64);
	free(payload64);
	free(token);
	return body;
}
