#!/bin/bash

# Load testing script for socket-based hybrid key exchange

SERVER_HOST=${1:-"127.0.0.1"}
SERVER_PORT=${2:-8080}
NUM_CLIENTS=${3:-10}

echo "Starting load test with $NUM_CLIENTS clients against $SERVER_HOST:$SERVER_PORT"

# Start clients in parallel
echo "Launching $NUM_CLIENTS clients..."
for i in $(seq 1 $NUM_CLIENTS); do
    ./client $SERVER_HOST > /dev/null 2>&1 &
    echo -n "."
done
echo ""

echo "Waiting for all clients to complete..."
wait

echo "Load test completed!"
echo "Check server output for results."