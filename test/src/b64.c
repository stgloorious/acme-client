#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../../src/b64.h"

int main(int argc, char **argv)
{
	unsigned char in[1024] = { 0 };
	char buf[1024];
	unsigned int len = atoi(argv[1]);
	if (argc != 3) {
		printf("Usage: b64 LENGTH FILENAME\n");
		;
		return -1;
	}

	FILE *fd;
	fd = fopen(argv[2], "r");
	if (fd == NULL) {
		fprintf(stderr, "Could not open file: %s\n", strerror(errno));
		return -1;
	}
	if (len != fread(in, sizeof(char), len, fd)) {
		fprintf(stderr, "did not read whole file.\n");
		return -1;
	}
	base64url(in, buf, len, sizeof(buf));
	printf("%s", buf);
	return 0;
}
