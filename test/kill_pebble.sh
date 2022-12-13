#!/bin/bash

pid_file="$TEST_DIR/pebble/pebble.pid"

if [[ -f "$pid_file" ]]; then
        if ps -p $(cat $pid_file) > /dev/null; then
                kill -9 $(cat $pid_file)
                echo "Killed Pebble server PID $(cat $pid_file)"
        else
                echo "Pebble PID $(cat $pid_file) is not running."
        fi
        rm $pid_file
else 
        echo "Could not find PID file $pid_file. Is Pebble running?"
fi
