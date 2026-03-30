#!/bin/bash
./server  --debug >> server_test.log 2>&1


# ./server 2>&1 | ts '[%Y-%m-%d %H:%M:%S]' > server_output.log &
# ./server 2>&1 > server_output.log &
# SERVER_PID=$!
# echo "Server started with PID $SERVER_PID"

# ./stats.sh server_test.log 
