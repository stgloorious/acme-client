#!/bin/bash

valgrind --show-reachable=no --leak-check=full --exit-on-first-error=yes --error-exitcode=255 ../acme-client
status=$?

# Expected exit code is 64
if [ "$status" -eq "64" ]; then
        exit 0;
fi
exit $status

