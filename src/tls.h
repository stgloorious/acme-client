/** 
 * @file tls.c
 * @brief Very minimal HTTPS/TLS server
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

struct https_args {
        uint16_t port;
        char* host;
};

SSL_CTX* tls_create_context();

uint8_t tls_conf_context(SSL_CTX *ctx);

void* https_cert_server(void* port);

uint8_t https_start(int16_t port, char* record, char* host);
