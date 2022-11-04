/** 
 * @file string.h
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

#include <assert.h>
#include <stdlib.h>

struct string_node {
        char* string;
        uint16_t strlen;
        struct string_node* next;
};

/**
 * @brief Allocates new node with given string and appends it.
 * @param[in] head head of the list, if NULL, new list is created
 * @param[in] new_string null terminated string that is copied into new node
 * @returns head
 */
struct string_node* 
string_list_append (struct string_node* head, char* new_string);

/** 
 * @brief Frees tail from the list and copies its string to buf
 * @param[in] head head of the list, cannot be NULL
 * @param[out] buf buffer of size @len where string from popped node is copied
 * @param[in] len size of @buf 
 * @returns head
 */
struct string_node*
string_list_pop_back (struct string_node* head, char* buf, uint16_t len);

struct string_node*
string_list_copy(struct string_node* head);

void string_list_delete(struct string_node* head);

void string_list_print(struct string_node* head);
