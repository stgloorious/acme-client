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

#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <cjson/cJSON.h>

#include "acme.h"
#include "string.h"
#include "http.h"
#include "err.h"

extern uint8_t verbose;
extern volatile sig_atomic_t int_shutdown;

const char *http_method_strings[] = { "GET",	"HEAD",	   "POST",    "PUT",
				      "DELETE", "CONNECT", "OPTIONS", "TRACE" };

void *http_chal_server(void *port)
{
	struct http_chal_args args = *((struct http_chal_args *)port);
	http_chal_start(args.port);
	return NULL;
}

int8_t http_chal_respond(struct http_msg *msg, char *token, int *con)
{
	/* status line */
	const size_t response_len = 256;
	char response[response_len];
	assert(msg->version == HTTP11);
	strncpy(response, "HTTP/1.1", response_len);
	uint8_t len = strlen(response);
	switch (msg->status) {
	case HTTP_STATUS_200_OK:
		strncpy(response + len, " 200 OK\r\n", response_len - len);
		break;
	default:
		DEBUG("Unknown status code!\n");
		return -1;
	}
	len = strlen(response);

	/* date header */
	strncpy(response + len, "Date: ", response_len - len);
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(response + len + 6, sizeof(response),
		 "%a, %d %b %Y %H:%M:%S %Z", &tm);

	len = strlen(response);
	strncpy(response + len,
		"\r\n"
		"Server: acme-client\r\n"
		"Content-Type: application/octet-stream\r\n\r\n",
		response_len - len);
	len = strlen(response);
	strncpy(response + len, token, response_len - len);
	send(*con, response, strlen(response), 0);
	shutdown(*con, SHUT_RDWR);
	return 0;
}

int8_t http_parse(char *buf, uint16_t len, struct http_msg *msg)
{
	/* copy the first line */
	char request_line[128];
	uint16_t i = 0;
	while (buf[i] != '\r' && i < len && i < sizeof(request_line)) {
		request_line[i] = buf[i];
		i++;
	}
	request_line[i] = '\0';
	char *split = strtok(request_line, " ");

	/* parse method, request target and version */
	if (split) {
		for (uint8_t i = 0; i < 8; i++) {
			if (!strcmp(http_method_strings[i], split)) {
				msg->method = i;
			}
		}
		split = strtok(NULL, " ");
	} else {
		ERROR("HTTP parse error\n");
		return -1;
	}
	if (split) {
		size_t len = strlen(split) + 1;
		msg->request_target = malloc(len);
		strncpy(msg->request_target, split, len);
		split = strtok(NULL, " ");
	} else {
		ERROR("HTTP parse error\n");
		return -1;
	}
	if (split) {
		for (uint8_t i = 0; i < 8; i++) {
			if (!strcmp("HTTP/1.1", split)) {
				msg->version = HTTP11;
			}
		}
		split = strtok(NULL, " ");
	} else {
		ERROR("Unsupported HTTP version!\n");
		return -1;
		/* TODO: return HTTP 505 */
	}
	if (split) {
		ERROR("HTTP parse error\n");
		return -1;
	}

	return 0;
}
int8_t http_chal_start(uint16_t port)
{
	/* open tcp socket */
	struct sockaddr_in6 me, other;
	int tcp_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	memset(&me, 0, sizeof(me));
	me.sin6_family = AF_INET6;
	me.sin6_port = htons(port);
	me.sin6_addr = in6addr_any;
	setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 },
		   sizeof(int));
	setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 },
		   sizeof(int));

	if (bind(tcp_socket, (struct sockaddr *)&me, sizeof(me))) {
		ERROR("HTTP challenge server bind failed.\n");
		close(tcp_socket);
		exit(-1);
		return -1;
	}
	listen(tcp_socket, 8);
	int flags = fcntl(tcp_socket, F_GETFL);
	flags |= O_NONBLOCK | SO_REUSEADDR;
	fcntl(tcp_socket, F_SETFL, flags);
	struct http_msg msg;
	char buf[1024];
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	int con = -1;

	while (!int_shutdown) {
		while (!int_shutdown && con < 1) {
			con = accept(tcp_socket, (struct sockaddr *)&other,
				     &addr_len);
		}
		if (!int_shutdown) {
			int16_t rsize = recv(con, buf, sizeof(buf), 0);
			if (rsize > 0) {
				if (http_parse(buf, sizeof(buf), &msg)) {
					ERROR("HTTP parsing failed.\n");
				} else {
					struct http_msg response;
					response.status = HTTP_STATUS_200_OK;
					response.version = HTTP11;
					char *token = acme_get_token(
						msg.request_target);
					http_chal_respond(&response, token,
							  &con);
					free(msg.request_target);
					free(token);
					con = -1;
				}
			}
		}
	}
	if (close(tcp_socket)) {
		ERROR("Could not close HTTP challenge socket\n");
	}
	DEBUG("Terminated HTTP challenge server\n");
	return 0;
}
