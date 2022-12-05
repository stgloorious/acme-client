#include <stdint.h>
#include <stdio.h>
#include "../src/string.h"

struct string_node *list = NULL;

uint16_t __atoi(char *str)
{
	int r = 0;
	for (int i = 0; str[i] != '\0'; i++) {
		r = r * 10 + str[i] - '0';
	}
	return r;
}

void test_empty_print()
{
	list = NULL;
	string_list_print(list);
	string_list_delete(list);
}

void test_append_single()
{
	list = NULL;
	list = string_list_append(list, "first_entry");
	string_list_print(list);
	string_list_delete(list);
}

void test_append_multiple()
{
	list = NULL;
	list = string_list_append(list, "first_entry");
	list = string_list_append(list, "second_entry");
	list = string_list_append(list, "third_entry");
	list = string_list_append(list, "123");
	list = string_list_append(list, "");
	list = string_list_append(list, "last###");
	string_list_print(list);
	string_list_delete(list);
}

void test_append_pop_mixed()
{
	char buf[32];
	list = NULL;
	list = string_list_append(list, "first_entry");
	list = string_list_append(list, "second_entry");
	list = string_list_pop_back(list, buf, sizeof(buf));
	printf("Removed %s\n", buf);
	list = string_list_append(list, "third_entry");
	list = string_list_pop_back(list, buf, sizeof(buf));
	printf("Removed %s\n", buf);
	list = string_list_pop_back(list, buf, sizeof(buf));
	printf("Removed %s\n", buf);
	string_list_print(list);
	string_list_delete(list);
}

void test_copy()
{
	list = NULL;
	list = string_list_append(list, "first_entry");
	list = string_list_append(list, "second_entry");
	list = string_list_append(list, "third_entry");

	struct string_node *copy = string_list_copy(list);
	string_list_print(copy);
	string_list_delete(list);
	string_list_delete(copy);
}

int main(int argc, char **argv)
{
	int choice = __atoi(argv[1]);
	if (argc != 2) {
		return -1;
	}
	switch (choice) {
	case 0:
		test_empty_print();
		break;
	case 1:
		test_append_single();
		break;
	case 2:
		test_append_multiple();
		break;
	case 3:
		test_append_pop_mixed();
		break;
	case 4:
		test_copy();
		break;
	}
	return 0;
}
