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
		size_t len = strlen(new_id->value) + 1;
		head->id->value = malloc(len);
		strncpy(head->id->value, new_id->value, len);
		head->id->type = new_id->type;
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
	size_t len = strlen(new_id->value) + 1;
	new_node->id->value = malloc(len);
	strncpy(new_node->id->value, new_id->value, len);
	new_node->id->type = new_id->type;
	current->next = new_node;
	return head;
}

struct id_node *id_list_copy(struct id_node *head)
{
	assert(head != NULL);

	struct id_node *prev = NULL;
	struct id_node *new_list = NULL;
	while (head != NULL) {
		struct id_node *new_node = malloc(sizeof(struct id_node));
		new_node->next = NULL;
		if (prev != NULL) {
			prev->next = new_node;
		} else {
			new_list = new_node;
		}
		new_node->id = malloc(sizeof(struct acme_identifier));
		new_node->id->type = head->id->type;
		size_t len = strlen(head->id->value) + 1;
		new_node->id->value = malloc(len);
		strncpy(new_node->id->value, head->id->value, len);
		prev = new_node;
		head = head->next;
	}
	return new_list;
}
struct id_node *id_list_pop_back(struct id_node *head,
				 struct acme_identifier *out)
{
	if (head == NULL)
		return NULL;

	/* traverse the list */
	struct id_node *current = head;
	struct id_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);
	if (out != NULL) {
		size_t len = strlen(current->id->value) + 1;
		out->value = malloc(len);
		strncpy(out->value, current->id->value, len);
		out->type = current->id->type;
	}
	if (head == current) {
		free(head->id->value);
		free(head->id);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->id->value);
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
		head->chal->status = new_chal->status;
		head->chal->type = new_chal->type;
		size_t len = strlen(new_chal->token) + 1;
		head->chal->token = malloc(len);
		strncpy(head->chal->token, new_chal->token, len);
		len = strlen(new_chal->url) + 1;
		head->chal->url = malloc(len);
		strncpy(head->chal->url, new_chal->url, len);
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
	new_node->chal->status = new_chal->status;
	new_node->chal->type = new_chal->type;
	size_t len = strlen(new_chal->token) + 1;
	new_node->chal->token = malloc(len);
	strncpy(new_node->chal->token, new_chal->token, len);
	len = strlen(new_chal->url) + 1;
	new_node->chal->url = malloc(len);
	strncpy(new_node->chal->url, new_chal->url, len);
	current->next = new_node;
	return head;
}

struct chal_node *chal_list_copy(struct chal_node *head)
{
	assert(head != NULL);

	struct chal_node *prev = NULL;
	struct chal_node *new_list = NULL;
	while (head != NULL) {
		struct chal_node *new_node = malloc(sizeof(struct chal_node));
		new_node->chal = malloc(sizeof(struct acme_chal));
		new_node->next = NULL;
		if (prev != NULL) {
			prev->next = new_node;
		} else {
			new_list = new_node;
		}
		size_t len = strlen(head->chal->token) + 1;
		new_node->chal->token = malloc(len);
		strncpy(new_node->chal->token, head->chal->token, len);
		len = strlen(head->chal->url) + 1;
		new_node->chal->url = malloc(len);
		strncpy(new_node->chal->url, head->chal->url, len);
		new_node->chal->status = head->chal->status;
		new_node->chal->type = head->chal->type;

		prev = new_node;
		head = head->next;
	}
	return new_list;
}

struct chal_node *chal_list_pop_back(struct chal_node *head,
				     struct acme_chal *out)
{
	if (head == NULL)
		return NULL;

	/* traverse the list */
	struct chal_node *current = head;
	struct chal_node *prev = head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}
	assert(current != NULL);
	if (out != NULL) {
		out->status = current->chal->status;
		out->type = current->chal->type;
		size_t len = strlen(current->chal->token) + 1;
		out->token = malloc(len);
		strncpy(out->token, current->chal->token, len);
		len = strlen(current->chal->url) + 1;
		out->url = malloc(len);
		strncpy(out->url, current->chal->url, len);
	}
	if (head == current) {
		free(head->chal->token);
		free(head->chal->url);
		free(head->chal);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		free(current->chal->token);
		free(current->chal->url);
		free(current->chal);
		free(current);
		return head;
	}
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
		head->auth->challenges = chal_list_copy(new_auth->challenges);
		head->auth->id = malloc(sizeof(struct acme_identifier));
		head->auth->id->type = new_auth->id->type;
		size_t len = strlen(new_auth->id->value) + 1;
		head->auth->id->value = malloc(len);
		strncpy(head->auth->id->value, new_auth->id->value, len);
		head->auth->status = new_auth->status;
		head->auth->wildcard = new_auth->wildcard;
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
	new_node->auth->challenges = chal_list_copy(new_auth->challenges);
	new_node->auth->id = malloc(sizeof(struct acme_identifier));
	new_node->auth->id->type = new_auth->id->type;
	size_t len = strlen(new_auth->id->value) + 1;
	new_node->auth->id->value = malloc(len);
	strncpy(new_node->auth->id->value, new_auth->id->value, len);
	new_node->auth->status = new_auth->status;
	new_node->auth->wildcard = new_auth->wildcard;
	current->next = new_node;
	return head;
}

struct authz_node *authz_list_copy(struct authz_node *head)
{
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
		out->id->type = head->auth->id->type;
		size_t len = strlen(head->auth->id->value) + 1;
		out->id->value = malloc(len);
		strncpy(out->id->value, head->auth->id->value, len);
		out->wildcard = head->auth->wildcard;
		out->status = head->auth->status;
		out->challenges = chal_list_copy(head->auth->challenges);
	}
	if (head == current) {
		chal_list_delete(head->auth->challenges);
		free(head->auth->id->value);
		free(head->auth->id);
		free(head->auth);
		free(head);
		return NULL;
	} else {
		prev->next = NULL;
		chal_list_delete(current->auth->challenges);
		free(current->auth->id->value);
		free(current->auth->id);
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
