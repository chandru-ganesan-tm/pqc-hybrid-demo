#!/bin/bash

set -euo pipefail

LOG_FILE=${1:-server_test.log}

if [[ ! -f "$LOG_FILE" ]]; then
    echo "Log file not found: $LOG_FILE" >&2
    exit 1
fi

awk '
/ECDHE keypair generation:/ { kp += $(NF-1); kp_count++ }
/ECDHE key derivation:/ { kd += $(NF-1); kd_count++ }
/Kyber decapsulation:/ { decap += $(NF-1); decap_count++ }
/Kyber encapsulation:/ { encap += $(NF-1); encap_count++ }
/Hybrid key derivation:/ { hk += $(NF-1); hk_count++ }
/Decryption:/ { dec += $(NF-1); dec_count++ }
/Encryption:/ { enc += $(NF-1); enc_count++ }
END {
    total = kp_count

    if (total == 0) {
        print "No timing metrics found in " FILENAME > "/dev/stderr"
        exit 1
    }

    print "Metrics from " FILENAME ":"
    print "Average ECDHE keypair generation: " (kp / kp_count) " milliseconds"
    print "Average ECDHE key derivation: " (kd / kd_count) " milliseconds"

    if (encap_count > 0) {
        print "Average Kyber encapsulation: " (encap / encap_count) " milliseconds"
    }

    if (decap_count > 0) {
        print "Average Kyber decapsulation: " (decap / decap_count) " milliseconds"
    }

    print "Average Hybrid key derivation: " (hk / hk_count) " milliseconds"

    if (enc_count > 0) {
        print "Average Encryption: " (enc / enc_count) " milliseconds"
    }

    if (dec_count > 0) {
        print "Average Decryption: " (dec / dec_count) " milliseconds"
    }

    print "Total connections processed: " total
}
' "$LOG_FILE"
