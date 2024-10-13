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

/** Parses the EC public key into X and Y values
 * @param[in] key
 * @param[out] x, malloc'd inside this function
 * @param[out] y, malloc'd inside this function
 */
void crypt_get_xy(EVP_PKEY **key, uint8_t **x, uint8_t **y);

int8_t crypt_new_key(EVP_PKEY **key);

int8_t crypt_read_key(EVP_PKEY **key, char *infile);

int8_t crypt_write_key(EVP_PKEY *key, char *outfile);

int8_t crypt_sign(const char *msg, EVP_PKEY *key, char *token, uint16_t tlen);

int8_t crypt_new_csr(EVP_PKEY **key, X509_REQ **csr, char *csr_pem,
		     uint16_t len, struct string_node *domain_list);

int8_t crypt_strip_csr(char *csr_pem, size_t len);

/**
 * @param[in] key private key used to sign the token
 * @param[in] header
 * @param[in] payload
 * @returns token, formatted for HTTP POST body
 */
char *crypt_mktoken(EVP_PKEY **key, char *header, char *payload);
