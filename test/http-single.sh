#!/bin/bash

echo "Starting Pebble testing server"
pebble -config "../../test/pebble-config.json" &
sleep 5 # Wait for server to come up

cmd="../acme-client --dir https://pebble:14000/dir --domain admin.example.com --cert=../../test/pebble.minica.pem --agree-tos http01"
echo "Running $cmd"
echo "$cmd" | bash
status=$?

killall pebble

exit $status
