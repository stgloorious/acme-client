/** 
 * @file crypt.c
 * @brief interface to libcrypto
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

int8_t crypt_new_key(EVP_PKEY** key);

int8_t crpyt_read_key(char* keyfile, uint16_t klen, const EVP_PKEY* key);

int8_t crypt_sign(const char* msg, EVP_PKEY* key, char* token, uint16_t tlen);

int8_t crypt_new_csr(EVP_PKEY** key, X509_REQ** csr, char* csr_pem, 
                uint16_t len, struct string_node* domain_list);

int8_t crypt_strip_csr(char* csr_pem);

int8_t crypt_strip_cert(char* cert_pem);