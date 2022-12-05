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

#include <openssl/evp.h>
#include <cjson/cJSON.h>

#include "acme.h"
#include "types.h"

/* ACME Identifier objects */
struct id_node *id_list_append(struct id_node *head,
			       struct acme_identifier *new_id)
{
	/* create list if needed */
	if (head == NULL) {
		head = malloc(sizeof(struct id_node));
		head->next = NULL;
		head->id = malloc(sizeof(struct acme_identifier));
		memcpy(head->id, new_id, sizeof(struct acme_identifier));
		return head;
	}
	/* if head already exists, traverse list */
	struct id_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	/* allocate new node and append to list */
	struct id_node *new_node = malloc(sizeof(struct id_node));
	new_node->next = NULL;
	new_node->id = malloc(sizeof(struct acme_identifier));
	memcpy(new_node->id, new_id, sizeof(struct acme_identifier));
	current->next = new_node;
	return head;
}

struct id_node *id_list_pop_back(struct id_node *head,
				 struct acme_identifier *out)
{
	assert(head != NULL);
	/* traverse the list */
	struct id_node *current = head;
	struct id_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);
	if (out != NULL) {
		memcpy(out, current->id, sizeof(struct acme_identifier));
	}
	if (head == current) {
		free(head->id);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->id);
		free(current);
	}
	return head;
}
void id_list_delete(struct id_node *list)
{
	while (list != NULL) {
		list = id_list_pop_back(list, NULL);
	}
}

/* ACME Challenge object */
struct chal_node *chal_list_append(struct chal_node *head,
				   struct acme_chal *new_chal)
{
	/* create list if needed */
	if (head == NULL) {
		head = malloc(sizeof(struct chal_node));
		head->next = NULL;
		head->chal = malloc(sizeof(struct acme_chal));
		memcpy(head->chal, new_chal, sizeof(struct acme_chal));
		return head;
	}
	/* if head already exists, traverse list */
	struct chal_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	/* allocate new node and append to list */
	struct chal_node *new_node = malloc(sizeof(struct chal_node));
	new_node->next = NULL;
	new_node->chal = malloc(sizeof(struct acme_chal));
	memcpy(new_node->chal, new_chal, sizeof(struct acme_chal));
	current->next = new_node;
	return head;
}

struct chal_node *chal_list_pop_back(struct chal_node *head,
				     struct acme_chal *out)
{
	assert(head != NULL);
	/* traverse the list */
	struct chal_node *current = head;
	struct chal_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);
	if (out != NULL) {
		memcpy(out, current->chal, sizeof(struct acme_chal));
	}
	if (head == current) {
		free(head->chal);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->chal);
		free(current);
	}
	return head;
}
void chal_list_delete(struct chal_node *list)
{
	while (list != NULL) {
		list = chal_list_pop_back(list, NULL);
	}
}

/* ACME Authorization object */
struct authz_node *authz_list_append(struct authz_node *head,
				     struct acme_auth *new_auth)
{
	/* create list if needed */
	if (head == NULL) {
		head = malloc(sizeof(struct authz_node));
		head->next = NULL;
		head->auth = malloc(sizeof(struct acme_auth));
		memcpy(head->auth, new_auth, sizeof(struct acme_chal));
		return head;
	}
	/* if head already exists, traverse list */
	struct authz_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	/* allocate new node and append to list */
	struct authz_node *new_node = malloc(sizeof(struct authz_node));
	new_node->next = NULL;
	new_node->auth = malloc(sizeof(struct acme_auth));
	memcpy(new_node->auth, new_auth, sizeof(struct acme_auth));
	current->next = new_node;
	return head;
}

struct authz_node *authz_list_pop_back(struct authz_node *head,
				       struct acme_auth *out)
{
	if (head == NULL)
		return NULL;
	/* traverse the list */
	struct authz_node *current = head;
	struct authz_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);

	if (out != NULL) {
		memcpy(out, current->auth, sizeof(struct acme_auth));
	}
	if (head == current) {
		free(head->auth);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->auth);
		free(current);
	}
	return head;
}
void authz_list_delete(struct authz_node *list)
{
	while (list != NULL) {
		list = authz_list_pop_back(list, NULL);
	}
}
