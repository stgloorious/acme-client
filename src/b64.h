/** 
 * @file b64.h
 * @brief base64url encoding
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
 * References: RFC 4648
 *
 */

/**
 * @brief encodes an array of bytes in base64
 * @param[in] in string to be encoded
 * @param[out] out base64 encoded string, null-terminated
 * @param[in] len_in strlen of @in
 * @param[in] len_out previously allocated size of @out array
 */
void base64(uint8_t* in, char* out, uint16_t len_in, uint16_t len_out);

/**
 * @brief encodes an array of bytes in base64 with url safe alphabet
 * @note this implementation of base64url does never add padding
 * @param[in] in string to be encoded
 * @param[out] out base64 encoded string, null-terminated
 * @param[in] len_in strlen of @in
 * @param[in] len_out previously allocated size of @out array
 */
void base64url(uint8_t* in, char* out, uint16_t len_in, uint16_t len_out);

void b64_normal2url(char* b64_string);

