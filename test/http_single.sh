#!/bin/bash

echo "Starting Pebble testing server"
pebble -config "../../test/pebble-config.json" &
sleep 5 # Wait for server to come up

cmd="../acme-client --dir https://pebble:14000/dir --domain example.com \
        --cert ../../test/pebble.minica.pem --agree-tos http01 --port 8080"
echo "Running $cmd"
echo "$cmd" | bash
status=$?

# Obtain the root certificate of the certificate chain that we obtained 
# through ACME
curl https://pebble:15000/roots/0 --silent --cacert ../test/pebble.minica.pem -o root.pem

if [[ $status -ne 0 ]]; then
        echo "Could not obtain certificate."
        exit -1
fi

# Start an HTTPS server with our newly obtained certificate
cat client.key cert.crt > cert.pem
python3 ../../test/https_server.py cert.pem &
sleep 1

# Curl the HTTPS server to check the certificate
curl https://example.com:5443 --cacert root.pem
status=$?

exit $status
