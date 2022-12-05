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

enum http_method { GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE };

enum http_version { HTTP11 };

#define HTTP_STATUS_200_OK 200

struct http_msg {
	enum http_method method;
	char *request_target;
	enum http_version version;
	uint16_t status;
};

struct http_chal_args {
	uint16_t port;
	char *host;
};

void *http_chal_server(void *port);

int8_t http_start(uint16_t port);

int8_t http_chal_start(uint16_t port);
