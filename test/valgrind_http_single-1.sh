#!/bin/sh

echo "Starting Pebble testing server"
pebble -config "../../test/pebble-config.json" &
pebble_pid=$!
sleep 5 # Wait for server to come up

cmd="valgrind --leak-check=full --exit-on-first-error=yes \
        --error-exitcode=255 ../acme-client \
        --dir https://pebble:14000/dir --domain example.com \
        --verbose --cert ../../test/pebble.minica.pem --agree-tos --port 8080"
echo "Running $cmd"
timeout 60 echo "$cmd" | bash
status=$?

if [[ $status -ne 0 ]]; then
        echo "Could not obtain certificate."
        kill $pebble_pid
        exit -1
fi

# Obtain the root certificate of the certificate chain that we obtained 
# through ACME
curl https://pebble:15000/roots/0 --silent --cacert ../../test/pebble.minica.pem -o root.pem

kill $pebble_pid

# Start an HTTPS server with our newly obtained certificate
cat client.key cert.crt > cert.pem
python3 ../../test/https_server.py cert.pem &
https_pid=$!
echo "Started HTTPS server with PID $https_pid"
sleep 1

# Curl the HTTPS server to check the certificate
curl https://example.com:5443 --cacert root.pem
status=$?

kill $https_pid
exit $status
