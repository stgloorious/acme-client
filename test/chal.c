#include <stdint.h>
#include <string.h>
#include <stdio.h>

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
struct chal_node *list = NULL;

void test_chal_list_create()
{
	struct acme_chal *new_chal = malloc(sizeof(struct acme_chal));
	new_chal->status = ACME_STATUS_UNKNOWN;
	new_chal->type = ACME_CHAL_HTTP01;
	new_chal->token = malloc(strlen("I am a token") + 1);
	strcpy(new_chal->token, "I am a token");
	new_chal->url = malloc(strlen("www.example.com") + 1);
	strcpy(new_chal->url, "www.example.com");
	list = chal_list_append(NULL, new_chal);
	free(new_chal->token);
	free(new_chal->url);
	free(new_chal);

	chal_list_delete(list);
}

int main(int argc, char **argv)
{
	int choice = __atoi(argv[1]);
	if (argc != 2) {
		return -1;
	}
	switch (choice) {
	case 0:
		test_chal_list_create();
		break;
	}
	return 0;
}
