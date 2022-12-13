#!/bin/bash

pid_file="$TEST_DIR/pebble/pebble.pid"
pebble_conf_path="$TEST_DIR/pebble/pebble-config.json"

# Configuration file of the pebble server is generated here
pebble_conf="\
{\
    \"pebble\": {\
    \"listenAddress\": \"$PEBBLE_HOSTNAME:$PEBBLE_LISTEN_PORT\",\
    \"managementListenAddress\": \"$PEBBLE_HOSTNAME:$PEBBLE_MGMT_PORT\",\
    \"certificate\": \"$TEST_DIR/pebble/pebble.crt\",\
    \"privateKey\": \"$TEST_DIR/pebble/pebble.key\",\
    \"httpPort\": $PEBBLE_HTTP_PORT,\
    \"tlsPort\": $PEBBLE_TLS_PORT,\
    \"ocspResponderURL\": \"\",\
    \"externalAccountBindingRequired\": false,\
    \"retryAfter\": {\
        \"authz\": 3,\
        \"order\": 5\
    }\
  }\
}"

# Check if pebble is installed
command -v pebble >> /dev/null
pebble_installed=$?

if [ $pebble_installed -ne 0 ]; then
        echo "Fatal error: Could not find Pebble. \
Make sure Pebble is installed and in your PATH."
        exit -1
fi

# Write configuration to json file
# It is nice if jq is installed so we can format it
# this is silently skipped if jq is not available because 
# it is not strictly necessary
command -v jq >> /dev/null
jq_installed=$?
if [ $jq_installed -eq 0 ]; then
        echo "$pebble_conf" | jq > "$pebble_conf_path"
else 
        echo "$pebble_conf" > "$pebble_conf_path"
fi

# Start pebble server and remember its pid
pebble -config "$pebble_conf_path" &
echo "$!" > $pid_file
sleep 5 # Wait for server to come up
echo "Started pebble server PID $(cat $pid_file)"

# Check if pebble is alive by sending a GET request
# to the dir resource
curl https://$PEBBLE_HOSTNAME:$PEBBLE_LISTEN_PORT/dir --silent \
        --cacert $TEST_DIR/pebble/pebble.minica.pem >> /dev/null
curl_stat=$?
if [ $curl_stat -ne 0 ]; then
        echo "Fatal error: Could not connect to  \
Pebble. Check the Pebble log and make sure \
Pebble can bind to port $PEBBLE_LISTEN_PORT."
        exit -1
fi
# Obtain the root certificate of the certificate chain 
# that we will obtain through ACME
curl https://$PEBBLE_HOSTNAME:$PEBBLE_MGMT_PORT/roots/0 --silent \
        --cacert $TEST_DIR/pebble/pebble.minica.pem -o "$PEBBLE_ROOT_CERT"
curl_stat=$?
if [ $curl_stat -ne 0 ]; then
        echo "Fatal error: Could not obtain root certificate \
from Pebble. Check the Pebble log and make sure \
Pebble can bind to port $PEBBLE_MGMT_PORT."
        exit -1
fi
