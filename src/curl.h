/** 
 * @file curl.h
 * @brief libcurl wrapper
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

int8_t curl_post( char* url, 
                  char* post,
                  void* write_cb,
                  void* header_cb,
                  char* header, 
                  char* ca_cert );

int8_t curl_get( char* url, 
                 void* header_cb, 
                 void* write_cb, 
                 char* ca_cert );

