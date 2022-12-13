#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/evp.h>
#include <cjson/cJSON.h>
#include "../src/types.h"
#include "../src/acme.h"

uint16_t __atoi(char *str)
{
	int r = 0;
	for (int i = 0; str[i] != '\0'; i++) {
		r = r * 10 + str[i] - '0';
	}
	return r;
}
struct id_node *list = NULL;

void test_id_list_create()
{
	struct acme_identifier *new_id = malloc(sizeof(struct acme_identifier));
	new_id->type = ACME_ID_DNS;
	new_id->value = malloc(strlen("I am an identifier") + 1);
	strcpy(new_id->value, "I am an identifier");
	list = id_list_append(NULL, new_id);

	free(new_id->value);
	free(new_id);

	id_list_delete(list);
}

void test_id_list_copy()
{
	struct acme_identifier *new_id = malloc(sizeof(struct acme_identifier));
	new_id->type = ACME_ID_DNS;
	new_id->value = malloc(strlen("I am an identifier") + 1);
	strcpy(new_id->value, "I am an identifier");
	list = id_list_append(NULL, new_id);
	assert(list != NULL);
	free(new_id->value);
	free(new_id);

	struct id_node *copy = id_list_copy(list);
	assert(copy != NULL);
	id_list_delete(list);

	struct acme_identifier *out = malloc(sizeof(struct acme_identifier));
	out->type = ACME_ID_DNS;
	out->value = NULL;
	assert(out != NULL);
	copy = id_list_pop_back(copy, out);
	assert(out != NULL);
	assert(out->value != NULL);

	if (strcmp(out->value, "I am an identifier")) {
		printf("String mismatch: got %s\n", out->value);
		exit(-1);
	}

	free(out->value);
	free(out);
}

int main(int argc, char **argv)
{
	int choice = __atoi(argv[1]);
	if (argc != 2) {
		return -1;
	}
	switch (choice) {
	case 0:
		test_id_list_create();
		break;
	case 1:
		test_id_list_copy();
		break;
	}
	return 0;
}
