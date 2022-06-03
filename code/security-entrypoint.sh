#!/bin/sh

while [ true ]; do
    echo "Sleeping for $SECURITY_SCAN_INTERVAL secs"
    sleep $SECURITY_SCAN_INTERVAL

    python security_main.py $@
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        exit $exit_code
    fi
done