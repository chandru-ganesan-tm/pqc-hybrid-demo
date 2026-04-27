/* ══════════════════════════════════════════════════════════════════
 *  PQC Hybrid Key Exchange — Client  (reference / native build)
 *
 *  Connects to the server, performs ECDH (X25519) + Kyber-768
 *  hybrid key exchange, encrypts a message and sends it.
 *
 *  Flags:
 *    --debug / -d     Verbose human-readable logging to stderr
 *    --json  / -j     Emit JSON event lines to stdout
 *                     (GUI reads these over the SSH pipe)
 *    <IP>             Optional server IP (default 192.168.0.100)
 * ══════════════════════════════════════════════════════════════════ */


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Includes & Defines
 * ────────────────────────────────────────────────────────────────── */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "./kyber/ref/api.h"
#include "./kyber/ref/kem.h"
#include "static_kyber_keys.h"

#define HYBRID_KEY_BYTES  32
#define SERVER_IP         "192.168.0.100"
#define SERVER_PORT       8080

static int server_port = SERVER_PORT;
#define MESSAGE           "Hello, this is a secret message from client!"

#define JSON_BUF          8192
#define HEX_SMALL         (64 + 1)
#define HEX_LARGE         (CRYPTO_PUBLICKEYBYTES * 2 + 1)
#define HEX_CT            (CRYPTO_CIPHERTEXTBYTES * 2 + 1)


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Globals & Debug Logging
 * ────────────────────────────────────────────────────────────────── */

static int debug     = 0;
static int json_mode = 0;

#define LOG(fmt, ...) \
    do { if (debug) fprintf(stderr, "[client] " fmt, ##__VA_ARGS__); } while (0)


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Utility — Timing & Socket Helpers
 * ────────────────────────────────────────────────────────────────── */

static double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

static ssize_t send_all(int fd, const void *buf, size_t len) {
    size_t total = 0;
    const unsigned char *p = buf;
    while (total < len) {
        ssize_t sent = send(fd, p + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

static ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    unsigned char *p = buf;
    while (total < len) {
        ssize_t recvd = recv(fd, p + total, len - total, 0);
        if (recvd <= 0) return recvd;
        total += recvd;
    }
    return total;
}


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: JSON Reporting
 *
 *  json_event() emits one JSON line to stdout when --json is active.
 *  The GUI reads these over the persistent SSH pipe.
 * ────────────────────────────────────────────────────────────────── */

static void to_hex(char *out, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

static void json_event(const char *fmt, ...) {
    if (!json_mode) return;

    char buf[JSON_BUF];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0 || n >= (int)sizeof(buf)) return;

    fwrite(buf, 1, n, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static void print_keysizes()
{
    const char *kyber_variant = "Kyber768";

    LOG("Key sizes:\n");

    if(KYBER_K == 2) {
        kyber_variant = "Kyber512";
        LOG("Kyber variant: Kyber512\n");
    } else if(KYBER_K == 3) {
        kyber_variant = "Kyber768";
        LOG("Kyber variant: Kyber768\n");
    } else if(KYBER_K == 4) {
        kyber_variant = "Kyber1024";
        LOG("Kyber variant: Kyber1024\n");
    }

    LOG("CRYPTO_PUBLICKEYBYTES (Kyber pubkey) = %d\n", CRYPTO_PUBLICKEYBYTES);
    LOG("crypto_kx_PUBLICKEYBYTES (ECDH pubkey) = %d\n", crypto_kx_PUBLICKEYBYTES);
    LOG("CRYPTO_SECRETKEYBYTES (kyber privkey) = %d\n", CRYPTO_SECRETKEYBYTES);
    LOG("crypto_kx_SECRETKEYBYTES (ecdhe privkey) = %d\n", crypto_kx_SECRETKEYBYTES);
    LOG("CRYPTO_BYTES (kyber shared secret) = %d\n", CRYPTO_BYTES);
    LOG("crypto_kx_SESSIONKEYBYTES (ecdhe shared secret) = %d\n", crypto_kx_SESSIONKEYBYTES);
    LOG("CRYPTO_CIPHERTEXTBYTES (kyber ciphertext) = %d\n", CRYPTO_CIPHERTEXTBYTES);
    LOG("HYBRID_KEY_BYTES (final symmetric key) = %d\n", HYBRID_KEY_BYTES);
    LOG("NONCEBYTES = %d\n", crypto_secretbox_NONCEBYTES);

    json_event("{\"event\":\"keysizes\",\"source\":\"client\","
               "\"kyber_variant\":\"%s\","
               "\"kyber_pk\":%d,\"ecdh_pk\":%d,"
               "\"kyber_sk\":%d,\"ecdh_sk\":%d,"
               "\"kyber_ss\":%d,\"ecdh_ss\":%d,"
               "\"kyber_ct\":%d,\"hybrid_key\":%d,\"nonce\":%d}",
               kyber_variant,
               CRYPTO_PUBLICKEYBYTES,
               crypto_kx_PUBLICKEYBYTES,
               CRYPTO_SECRETKEYBYTES,
               crypto_kx_SECRETKEYBYTES,
               CRYPTO_BYTES,
               crypto_kx_SESSIONKEYBYTES,
               CRYPTO_CIPHERTEXTBYTES,
               HYBRID_KEY_BYTES,
               crypto_secretbox_NONCEBYTES);
}



/* ══════════════════════════════════════════════════════════════════
 *  SECTION: main()
 * ══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {

    /* ── Argument Parsing ──────────────────────────────────────── */

    const char *server_ip = SERVER_IP;
    const char *message = MESSAGE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_mode = 1;
        } else if ((strcmp(argv[i], "--msg") == 0 || strcmp(argv[i], "-m") == 0)
                   && i + 1 < argc) {
            message = argv[++i];
        } else if ((strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0)
                   && i + 1 < argc) {
            server_port = atoi(argv[++i]);
        } else {
            server_ip = argv[i];
        }
    }


    /* ── libsodium Init ────────────────────────────────────────── */

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    print_keysizes();

    /* ── Connect to Server ─────────────────────────────────────── */

    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("invalid address");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        return 1;
    }

    LOG("Connected to server %s:%d\n", server_ip, server_port);
    json_event("{\"event\":\"connected\",\"server\":\"%s:%d\"}",
               server_ip, server_port);


    /* ── 1. Receive Server Public Keys ─────────────────────────── */

    unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];

    if (recv_all(sock, recv_kx_pk, crypto_kx_PUBLICKEYBYTES)
            != crypto_kx_PUBLICKEYBYTES) {
        perror("Failed to receive server ECDH public key");
        close(sock); return 1;
    }

    if (recv_all(sock, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES)
            != CRYPTO_PUBLICKEYBYTES) {
        perror("Failed to receive server Kyber public key");
        close(sock); return 1;
    }

    LOG("Received server public keys\n");

    {
        char hex_ecdh[HEX_SMALL];
        char hex_kyber[HEX_LARGE];
        to_hex(hex_ecdh, recv_kx_pk, crypto_kx_PUBLICKEYBYTES);
        to_hex(hex_kyber, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES);
        json_event("{\"event\":\"server_keys_received\","
                   "\"ecdh_pk\":\"%s\",\"kyber_pk\":\"%s\"}",
                   hex_ecdh, hex_kyber);
    }


    /* ── 2. Client ECDH Keygen ─────────────────────────────────── */

    struct timespec ts_start, ts_end;
    double ecdhe_keypair_time, ecdhe_derive_time,
           kyber_encap_time, key_derivation_time, encryption_time;

    unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sender_kx_sk[crypto_kx_SECRETKEYBYTES];

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    if (crypto_kx_keypair(sender_kx_pk, sender_kx_sk) != 0) {
        fprintf(stderr, "ECDH keypair generation failed\n");
        close(sock); return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    ecdhe_keypair_time = get_time_diff(ts_start, ts_end) * 1000;

    {
        char hex[HEX_SMALL];
        to_hex(hex, sender_kx_pk, crypto_kx_PUBLICKEYBYTES);
        json_event("{\"event\":\"ecdh_keygen\","
                   "\"pk\":\"%s\",\"time_ms\":%.6f}",
                   hex, ecdhe_keypair_time);
    }


    /* ── 3. ECDH Shared Secret ─────────────────────────────────── */

    unsigned char cli_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char cli_tx[crypto_kx_SESSIONKEYBYTES];

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    if (crypto_kx_client_session_keys(cli_rx, cli_tx,
            sender_kx_pk, sender_kx_sk, recv_kx_pk) != 0)
    {
        fprintf(stderr, "ECDH client key derivation failed\n");
        close(sock); return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    ecdhe_derive_time = get_time_diff(ts_start, ts_end) * 1000;

    unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared, cli_tx, crypto_kx_SESSIONKEYBYTES);

    {
        char hex[HEX_SMALL];
        to_hex(hex, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
        json_event("{\"event\":\"ecdh_derive\","
                   "\"shared\":\"%s\",\"time_ms\":%.6f}",
                   hex, ecdhe_derive_time);
    }


    /* ── 4. Kyber Encapsulation ────────────────────────────────── */

    unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char kyber_ss[CRYPTO_BYTES];

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    if (crypto_kem_enc(kyber_ct, kyber_ss, recv_kyber_pk) != 0) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        close(sock); return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    kyber_encap_time = get_time_diff(ts_start, ts_end) * 1000;

    {
        char hex_ct[HEX_CT];
        char hex_ss[HEX_SMALL];
        to_hex(hex_ct, kyber_ct, CRYPTO_CIPHERTEXTBYTES);
        to_hex(hex_ss, kyber_ss, CRYPTO_BYTES);
        json_event("{\"event\":\"kyber_encap\","
                   "\"ct\":\"%s\",\"shared\":\"%s\",\"time_ms\":%.6f}",
                   hex_ct, hex_ss, kyber_encap_time);
    }


    /* ── 5. Hybrid Key Derivation ──────────────────────────────── */

    unsigned char hybrid_key[HYBRID_KEY_BYTES];
    unsigned char kdf_input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(kdf_input, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    memcpy(kdf_input + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    crypto_hash_sha256(hybrid_key, kdf_input, sizeof(kdf_input));
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    key_derivation_time = get_time_diff(ts_start, ts_end) * 1000;

    {
        char hex[HEX_SMALL];
        to_hex(hex, hybrid_key, HYBRID_KEY_BYTES);
        json_event("{\"event\":\"hybrid_key\","
                   "\"key\":\"%s\",\"time_ms\":%.6f}",
                   hex, key_derivation_time);
    }


    /* ── 6. Encrypt Message ────────────────────────────────────── */

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t message_len = strlen(message);
    unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    crypto_secretbox_easy(ciphertext, (const unsigned char *)message,
                          message_len, nonce, hybrid_key);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    encryption_time = get_time_diff(ts_start, ts_end) * 1000;

    {
        char hex_ct[sizeof(ciphertext) * 2 + 1];
        char hex_nonce[crypto_secretbox_NONCEBYTES * 2 + 1];
        to_hex(hex_ct, ciphertext, sizeof(ciphertext));
        to_hex(hex_nonce, nonce, crypto_secretbox_NONCEBYTES);
        json_event("{\"event\":\"encrypt\","
                   "\"ciphertext\":\"%s\",\"nonce\":\"%s\",\"time_ms\":%.6f}",
                   hex_ct, hex_nonce, encryption_time);
    }


    /* ── 7. Send Data to Server ────────────────────────────────── */

    if (send_all(sock, sender_kx_pk, crypto_kx_PUBLICKEYBYTES)
            != crypto_kx_PUBLICKEYBYTES ||
        send_all(sock, kyber_ct, CRYPTO_CIPHERTEXTBYTES)
            != CRYPTO_CIPHERTEXTBYTES ||
        send_all(sock, nonce, crypto_secretbox_NONCEBYTES)
            != crypto_secretbox_NONCEBYTES)
    {
        perror("Failed to send client data");
        close(sock); return 1;
    }

    uint32_t ciphertext_len_net = htonl(sizeof(ciphertext));
    if (send_all(sock, &ciphertext_len_net, sizeof(uint32_t))
            != sizeof(uint32_t) ||
        send_all(sock, ciphertext, sizeof(ciphertext))
            != sizeof(ciphertext))
    {
        perror("Failed to send ciphertext");
        close(sock); return 1;
    }

    LOG("Sent encrypted message to server\n");
    json_event("{\"event\":\"data_sent\"}");


    /* ── 8. Receive Response & Report Timing ───────────────────── */

    int valread = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (valread > 0) {
        buffer[valread] = '\0';
        LOG("Server response: %s\n", buffer);
        printf("Server response: %s\n", buffer);
        json_event("{\"event\":\"complete\",\"response\":\"%s\"}", buffer);
    }

    LOG("Timing Results:\n");
    LOG("  ECDHE keypair generation: %.6f ms\n", ecdhe_keypair_time);
    LOG("  ECDHE key derivation:     %.6f ms\n", ecdhe_derive_time);
    LOG("  Kyber encapsulation:      %.6f ms\n", kyber_encap_time);
    LOG("  Hybrid key derivation:    %.6f ms\n", key_derivation_time);
    LOG("  Encryption:               %.6f ms\n", encryption_time);

    close(sock);
    LOG("Connection closed\n");

    return 0;
}
