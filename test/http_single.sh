#!/bin/sh

cmd="$ACME_BIN --dir https://$PEBBLE_HOSTNAME:$PEBBLE_LISTEN_PORT/dir \
--domain $DOMAIN \
--verbose \
--cert $TEST_DIR/pebble/pebble.minica.pem \
--agree-tos \
--port $PEBBLE_HTTP_PORT"

$TEST_DIR/start_pebble.sh
pebble_stat=$?
if [[ $pebble_stat -ne 0 ]]; then
        $TEST_DIR/kill_pebble.sh
        exit -1
fi

echo "Running $cmd"
echo "$cmd" | bash
status=$?

$TEST_DIR/kill_pebble.sh

if [[ $status -ne 0 ]]; then
        echo "Executable exited with code $status: Test FAILED."
        exit -1
fi

# Check for python (needed for HTTPS testing server)
command -v python3 || exit -1
cat $ACME_OUT_DIR/client.key $ACME_OUT_DIR/cert.crt > cert.pem

# Start an HTTPS server with our newly obtained certificate
validate_port=5443
python3 $TEST_DIR/https_server.py $ACME_OUT_DIR/cert.pem $validate_port &
https_pid=$!
echo "Started HTTPS server on port $validate_port with PID $https_pid"
sleep 1

# Curl the HTTPS server to check the certificate
curl https://$DOMAIN:$validate_port --cacert $PEBBLE_ROOT_CERT
status=$?

if ps -p $https_pid > /dev/null; then
        kill $https_pid
        echo "Killed HTTPS server PID $https_pid"
fi

exit $status
