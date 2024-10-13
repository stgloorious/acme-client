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
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "string.h"

struct string_node *string_list_append(struct string_node *head,
				       char *new_string)
{
	/* create list if needed */
	if (head == NULL) {
		head = malloc(sizeof(struct string_node));
		head->next = NULL;
		size_t len = strlen(new_string) + 1;
		head->string = malloc(len);
		strncpy(head->string, new_string, len);
		head->strlen = strlen(head->string);
		return head;
	}
	/* if head already exists, traverse list */
	struct string_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	/* allocate new node and append to list */
	struct string_node *new_node = malloc(sizeof(struct string_node));
	new_node->next = NULL;
	size_t len = strlen(new_string) + 1;
	new_node->string = malloc(len);
	strncpy(new_node->string, new_string, len);
	new_node->strlen = strlen(new_node->string);
	current->next = new_node;
	return head;
}

struct string_node *string_list_pop_back(struct string_node *head, char *buf,
					 uint16_t len)
{
	assert(head != NULL);
	/* traverse the list */
	struct string_node *current = head;
	struct string_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);
	if ((buf != NULL) && (len > 0)) {
		strncpy(buf, current->string, len);
	}
	if (head == current) {
		free(head->string);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->string);
		free(current);
	}
	return head;
}

struct string_node *string_list_copy(struct string_node *list)
{
	assert(list != NULL);
	struct string_node *copy;
	copy = malloc(sizeof(struct string_node));
	copy->next = NULL;
	char *str = list->string;
	size_t len = strlen(str) + 1;
	copy->string = malloc(len);
	strncpy(copy->string, list->string, len);
	copy->strlen = list->strlen;

	struct string_node *current_orig = list->next;
	struct string_node *current_copy = copy;
	struct string_node *prev_copy;
	while (current_orig != NULL) {
		prev_copy = current_copy;
		current_copy = malloc(sizeof(struct string_node));
		prev_copy->next = current_copy;
		current_copy->next = NULL;
		len = strlen(current_orig->string) + 1;
		current_copy->string = malloc(len);
		strncpy(current_copy->string, current_orig->string, len);
		current_copy->strlen = current_orig->strlen;

		current_orig = current_orig->next;
	}
	return copy;
}

void string_list_delete(struct string_node *list)
{
	while (list != NULL) {
		list = string_list_pop_back(list, NULL, 0);
	}
}

void string_list_print(struct string_node *list)
{
	if (list == NULL) {
		printf("<empty list>\n");
	} else {
		struct string_node *curr = list;
		int i = 0;
		while (curr != NULL) {
			printf("[%i] %s %i\n", i++, curr->string, curr->strlen);
			curr = curr->next;
		}
	}
}
