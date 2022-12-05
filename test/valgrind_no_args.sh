#!/bin/bash

valgrind --show-leak-kinds=all --leak-check=full --exit-on-first-error=yes --error-exitcode=255 ../acme-client
