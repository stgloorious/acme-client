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
 * References: RFC 4648
 *
 */

#include <stdint.h>
#include <assert.h>
#include <stdio.h>

const char *b64_alphabet = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz"
			     "0123456789+/" };

const char *b64url_alphabet = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789-_" };

void base64(uint8_t *in, char *out, uint16_t len_in, uint16_t len_out)
{
	uint16_t out_index = 0;
	uint16_t i = 0;
	for (i = 0; i < len_in; i++) {
		assert(len_out > out_index);
		switch (i % 3) {
		case 0:
			*(out + out_index) =
				b64_alphabet[((uint8_t)(*(in + i) & 0xfc) >> 2) &
					     0x3f];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) = (((*(in + i) & 0x03) << 4) & 0x30);
			break;
		case 1:
			*(out + out_index) |=
				(((*(in + i) & 0xf0) >> 4) & 0x0f);
			assert(*(out + out_index) < 64);
			*(out + out_index) =
				b64_alphabet[(uint8_t)(*(out + out_index))];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) = ((*(in + i) & 0x0f) << 2) & 0x3c;
			break;
		case 2:
			*(out + out_index) |= ((*(in + i) & 0xc0) >> 6) & 0x03;
			assert(*(out + out_index) < 64);
			*(out + out_index) =
				b64_alphabet[(uint8_t) * (out + out_index)];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) =
				b64_alphabet[((uint8_t)(*(in + i) & 0x3f)) &
					     0x3f];
			out_index++;
			break;
		}
	}

	/* check if we need padding */
	if (i % 3 == 1) { /* two padding characters required */
		assert(len_out > out_index);
		*(out + out_index) =
			b64_alphabet[((uint8_t)(*(in + i - 1) & 0x03) << 4)];
		out_index++;
		assert(len_out > out_index);
		*(out + out_index) = '=';
		out_index++;
		assert(len_out > out_index);
		*(out + out_index) = '=';
		out_index++;
	}
	if (i % 3 == 2) { /* one padding character required */
		assert(len_out > out_index);
		*(out + out_index) |= (*(in + i - 1) & 0x0f) << 2;
		*(out + out_index) =
			b64_alphabet[(uint8_t) * (out + out_index)];
		out_index++;
		assert(len_out > out_index);
		*(out + out_index) = '=';
		out_index++;
	}

	assert(len_out > out_index);
	out[out_index] = '\0';
}

void base64url(uint8_t *in, char *out, uint16_t len_in, uint16_t len_out)
{
	uint16_t out_index = 0;
	uint16_t i = 0;
	for (i = 0; i < len_in; i++) {
		assert(len_out > out_index);
		switch (i % 3) {
		case 0:
			*(out + out_index) = b64url_alphabet
				[((uint8_t)(*(in + i) & 0xfc) >> 2) & 0x3f];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) = (((*(in + i) & 0x03) << 4) & 0x30);
			break;
		case 1:
			*(out + out_index) |=
				(((*(in + i) & 0xf0) >> 4) & 0x0f);
			assert(*(out + out_index) < 64);
			*(out + out_index) =
				b64url_alphabet[(uint8_t)(*(out + out_index))];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) = ((*(in + i) & 0x0f) << 2) & 0x3c;
			break;
		case 2:
			*(out + out_index) |= ((*(in + i) & 0xc0) >> 6) & 0x03;
			assert(*(out + out_index) < 64);
			*(out + out_index) =
				b64url_alphabet[(uint8_t) * (out + out_index)];
			out_index++;
			assert(len_out > out_index);
			*(out + out_index) =
				b64url_alphabet[((uint8_t)(*(in + i) & 0x3f)) &
						0x3f];
			out_index++;
			break;
		}
	}
	switch (i % 3) {
	case 0:
		//out[out_index-1] = '\0';
		break;
	case 1:
		*(out + out_index) =
			b64url_alphabet[(uint8_t)(*(out + out_index))];
		out_index++;
		break;
	case 2:
		*(out + out_index) =
			b64url_alphabet[(uint8_t)(*(out + out_index))];
		out_index++;
		break;
	}

	assert(len_out > out_index);
	out[out_index] = '\0';
}

void b64_normal2url(char *b64_string)
{
	while (*b64_string != '\0') {
		if (*b64_string == '/') {
			*b64_string = '_';
		}
		if (*b64_string == '+') {
			*b64_string = '-';
		}
		if (*b64_string == '=') {
			*b64_string = '\0';
		}
		b64_string++;
	}
}
