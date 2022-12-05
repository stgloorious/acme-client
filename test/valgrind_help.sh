#!/bin/bash

valgrind --show-reachable=no --leak-check=full --exit-on-first-error=yes --error-exitcode=255 ../acme-client --help
