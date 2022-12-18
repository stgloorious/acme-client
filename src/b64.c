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
#include <math.h>

const char *b64url_alphabet = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789-_" };

void base64url(uint8_t *in, char *out, uint16_t len_in, uint16_t len_out)
{
	/* The output is ceil(4/3)*len_in plus room for \0 at the end */
	assert(len_out > (ceil((4.0 / 3.0) * len_in)));

	uint16_t oindex = 0; //index of the output string
	uint16_t iindex = 0; //index of the input string
	for (iindex = 0; iindex < len_in; iindex++) {
		/* depending on the relative position of the input 
                 * character (mod 3), it influences 2 of the 4 output characters
                 * for each 3 letter input */
		switch (iindex % 3) {
		case 0:
			*(out + oindex) = b64url_alphabet
				[((uint8_t)(*(in + iindex) & 0xfc) >> 2) & 0x3f];
			oindex++;
			*(out + oindex) =
				(((*(in + iindex) & 0x03) << 4) & 0x30);
			break;
		case 1:
			*(out + oindex) |=
				(((*(in + iindex) & 0xf0) >> 4) & 0x0f);
			*(out + oindex) =
				b64url_alphabet[(uint8_t)(*(out + oindex))];
			oindex++;
			*(out + oindex) = ((*(in + iindex) & 0x0f) << 2) & 0x3c;
			break;
		case 2:
			*(out + oindex) |= ((*(in + iindex) & 0xc0) >> 6) &
					   0x03;
			*(out + oindex) =
				b64url_alphabet[(uint8_t) * (out + oindex)];
			oindex++;
			*(out + oindex) = b64url_alphabet
				[((uint8_t)(*(in + iindex) & 0x3f)) & 0x3f];
			oindex++;
			break;
		}
	}
	switch (iindex % 3) {
	case 0:
		break;
	case 1:
		*(out + oindex) = b64url_alphabet[(uint8_t)(*(out + oindex))];
		oindex++;
		break;
	case 2:
		*(out + oindex) = b64url_alphabet[(uint8_t)(*(out + oindex))];
		oindex++;
		break;
	}
	out[oindex] = '\0';
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
