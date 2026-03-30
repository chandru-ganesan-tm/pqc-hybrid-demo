#!/bin/bash

# Load testing script for socket-based hybrid key exchange

SERVER_HOST=${1:-"127.0.0.1"}
SERVER_PORT=${2:-8080}
NUM_CLIENTS=${3:-10}
BATCH_SIZE=${4:-40}
CLIENT_DEBUG=${5:-0}

echo "Starting load test with $NUM_CLIENTS clients against $SERVER_HOST:$SERVER_PORT"
echo "Batch size: $BATCH_SIZE"

# Assume server is started manually (do not auto-start in this load test)
echo "Assuming server is already running at $SERVER_HOST:$SERVER_PORT"

# cleanup old logs
# rm -f server_output.log client_output.log


# Start clients in parallel
echo "Launching $NUM_CLIENTS clients in batches..."

completed=0
failed=0
batch_launched=0
pids=()

for i in $(seq 1 "$NUM_CLIENTS"); do
    if [ "$CLIENT_DEBUG" -eq 1 ]; then
        ./client --debug "$SERVER_HOST" >> ./client_test.log 2>&1 &
    else
        ./client "$SERVER_HOST" >> ./client_test.log 2>&1 &
    fi

    pids+=("$!")
    batch_launched=$((batch_launched + 1))
    echo -n "."

    if [ "$batch_launched" -ge "$BATCH_SIZE" ]; then
        for pid in "${pids[@]}"; do
            if wait "$pid"; then
                completed=$((completed + 1))
            else
                failed=$((failed + 1))
            fi
        done
        pids=()
        batch_launched=0
    fi
done

# Wait for any remaining clients in the final partial batch.
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        completed=$((completed + 1))
    else
        failed=$((failed + 1))
    fi
done

echo ""
echo "Completed: $completed / $NUM_CLIENTS, Failed: $failed"

# Kill server
# echo "Stopping server..."
# kill $SERVER_PID
# wait $SERVER_PID 2>/dev/null

echo "Load test completed!"

# Parse server output for averages
# echo "Calculating averages from server timing results..."

# awk '
# /ECDHE keypair generation:/ { kp += $4; kp_count++ }
# /ECDHE key derivation:/ { kd += $4; kd_count++ }
# /Kyber decapsulation:/ { decap += $4; decap_count++ }
# /Hybrid key derivation:/ { hk += $4; hk_count++ }
# /Decryption:/ { dec += $4; dec_count++ }
# END {
#     if (kp_count > 0) print "Average ECDHE keypair generation: " kp / kp_count " seconds"
#     if (kd_count > 0) print "Average ECDHE key derivation: " kd / kd_count " seconds"
#     if (decap_count > 0) print "Average Kyber decapsulation: " decap / decap_count " seconds"
#     if (hk_count > 0) print "Average Hybrid key derivation: " hk / hk_count " seconds"
#     if (dec_count > 0) print "Average Decryption: " dec / dec_count " seconds"
#     print "Total connections processed: " kp_count
# }
# ' server_output.log

# echo "Check server_output.log for detailed results."