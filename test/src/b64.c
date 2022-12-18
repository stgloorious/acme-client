#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../../src/b64.h"

int main(int argc, char **argv)
{
	unsigned char *in;
	char *buf;
	unsigned int len = atoi(argv[1]);
	if (argc != 4) {
		printf("Usage: b64 INPUT_LENGTH OUTPUT_LENGTH FILENAME\n");
		;
		goto fail;
	}
	in = malloc(len);
	buf = malloc(atoi(argv[2]));

	FILE *fd;
	fd = fopen(argv[3], "r");
	if (fd == NULL) {
		fprintf(stderr, "Could not open file: %s\n", strerror(errno));
		goto fail;
	}
	if (len != fread(in, sizeof(char), len, fd)) {
		fprintf(stderr, "did not read whole file.\n");
		goto fail;
	}
	fclose(fd);
	base64url(in, buf, len, atoi(argv[2]));
	printf("%s", buf);
	goto success;
fail:
	free(buf);
	free(in);
	return -1;
success:
	free(buf);
	free(in);
	return 0;
}
