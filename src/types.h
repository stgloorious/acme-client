/** 
 * @file id_list.c
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

struct id_node {
        struct acme_identifier* id;
        struct id_node* next;       
};

struct chal_node {
        struct acme_chal* chal;     
        struct chal_node* next;
};

struct authz_node {
       struct acme_auth* auth;
       struct authz_node* next;
};

struct id_node* 
id_list_append (struct id_node* head, struct acme_identifier* new_id);

struct id_node*
id_list_pop_back (struct id_node* head, struct acme_identifier* out);

struct chal_node* 
chal_list_append (struct chal_node* head, struct acme_chal* new_id);

struct chal_node*
chal_list_pop_back (struct chal_node* head, struct acme_chal* out);

struct authz_node* 
authz_list_append (struct authz_node* head, struct acme_auth* new_id);

struct authz_node*
authz_list_pop_back (struct authz_node* head, struct acme_auth* out);

void id_list_delete(struct id_node* list);

