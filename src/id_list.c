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

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <cjson/cJSON.h>

#include "acme.h"
#include "id_list.h"

struct id_node* 
id_list_append (struct id_node* head, struct acme_identifier* new_id){
        /* create list if needed */
        if (head == NULL) {
                head = malloc(sizeof(struct id_node));
                head->next = NULL;
                head->id = malloc(sizeof(struct acme_identifier));
                memcpy(head->id, new_id, sizeof(struct acme_identifier));
                return head;
        }
        /* if head already exists, traverse list */
        struct id_node* current = head;
        while (current->next != NULL){
                current = current->next;
        }
        /* allocate new node and append to list */
        struct id_node* new_node = malloc(sizeof(struct id_node));
        new_node->next = NULL;
        new_node->id = malloc(sizeof(struct acme_identifier));
        memcpy(new_node->id, new_id, sizeof(struct acme_identifier));
        current->next = new_node;
        return head;
}

struct id_node*
id_list_pop_back (struct id_node* head, struct acme_identifier* out) {
        assert(head != NULL);
        /* traverse the list */
        struct id_node* current = head;
        struct id_node* prev = head;
        while (current->next != NULL){
                prev = current;
                current = current->next;
        }
        assert(current != NULL); 
        if (head == current){
                free(head->id);
                free(head);
                return NULL;
        }
        else {
                prev->next = NULL;
                free(current->id);
                free(current);
        }
        return head;
}
//TODO implement
/*
struct id_node* id_list_copy(struct id_node* list){
        assert(list != NULL);
        struct id_node* copy;
        copy = malloc(sizeof(struct id_node));
        copy->next = NULL;
        char* str = list->string;
        int len = strlen(str) + 1;
        copy->string = malloc(len);
        strcpy(copy->string, list->string);
        copy->strlen = list->strlen;

        struct id_node* current_orig = list->next;
        struct id_node* current_copy = copy;
        struct id_node* prev_copy = copy;
        while (current_orig != NULL){
       
                prev_copy = current_copy;
                current_copy = malloc(sizeof(struct id_node));
                prev_copy->next = current_copy;
                current_copy->next = NULL;
                current_copy->string = malloc(strlen(current_orig->string)+1);
                strcpy(current_copy->string, current_orig->string);
                current_copy->strlen = current_orig->strlen;
                
                current_orig = current_orig->next;
        }
        return copy;
}
*/
void id_list_delete(struct id_node* list){
        while (list != NULL){
                list = id_list_pop_back(list, NULL);
        }
}

