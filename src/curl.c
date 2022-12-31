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

#include <stdint.h>
#include <curl/curl.h>
#include "curl.h"
#include "err.h"

int8_t curl_post(char *url, char *post, void *write_cb, void *header_cb,
		 char *headers, char *ca_cert)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *slist1;

	slist1 = NULL;
	slist1 = curl_slist_append(slist1,
				   "Content-Type: application/jose+json");

	struct curl_packet_info info;
	info.buffer = NULL;
	info.received = 0;
	info.total_length = 0;

	if (headers != NULL) {
		slist1 = curl_slist_append(slist1, headers);
	}
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
				 (long)CURL_HTTP_VERSION_1_1);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
		if (write_cb)
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
		if (header_cb)
			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,
					 header_cb);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &info);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &info);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			ERROR("curl error: %s\n", curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			curl_slist_free_all(slist1);
			return -1;
		}
	} else {
		ERROR("libcurl error.\n");
		curl_easy_cleanup(curl);
		curl_slist_free_all(slist1);
		return -1;
	}
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist1);
	return 0;
}

int8_t curl_get(char *url, void *header_cb, void *write_cb, char *ca_cert)
{
	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();

	struct curl_packet_info info;
	info.buffer = NULL;
	info.received = 0;
	info.total_length = 0;

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
				 (long)CURL_HTTP_VERSION_1_1);
		if (header_cb)
			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,
					 header_cb);
		if (write_cb)
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &info);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &info);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			ERROR("curl error: %s\n", curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			return -1;
		}
		uint64_t scode;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &scode);
		if ((scode < 200) || (scode >= 300)) {
			ERROR("curl error: status code %lu\n", scode);
			curl_easy_cleanup(curl);
			return -1;
		}
	} else {
		curl_easy_cleanup(curl);
		return -1;
	}
	curl_easy_cleanup(curl);
	return 0;
}
