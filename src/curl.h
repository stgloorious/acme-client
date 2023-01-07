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

struct curl_packet_info {
	char *buffer;
	uint32_t received;
	uint32_t total_length;
	uint8_t chunked;
};

void curl_init();

void curl_cleanup();

int8_t curl_post(char *url, char *post, void *write_cb, void *header_cb,
		 char *header, char *ca_cert);

int8_t curl_get(char *url, void *header_cb, void *write_cb, char *ca_cert);
