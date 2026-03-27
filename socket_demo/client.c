#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../kyber/ref/api.h"
#include "../kyber/ref/kem.h"
#include "../demo/static_kyber_keys.h"

#define HYBRID_KEY_BYTES 32   // 256-bit symmetric key
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define MESSAGE "Hello, this is a secret message from client!"

static double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

static int debug = 0;
#define LOG(fmt, ...) do { if (debug) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

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

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    struct timespec start, end;
    double ecdhe_keypair_time = 0, ecdhe_derive_time = 0, kyber_encap_time = 0, key_derivation_time = 0, encryption_time = 0;

    // Debug switch
    if (argc > 1 && (strcmp(argv[1], "--debug") == 0 || strcmp(argv[1], "-d") == 0)) {
        debug = 1;
    }

    // Allow custom server IP via command line argument
    const char *server_ip = SERVER_IP;
    if (argc > 1 && !(strcmp(argv[1], "--debug") == 0 || strcmp(argv[1], "-d") == 0)) {
        server_ip = argv[1];
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IP address
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("invalid address");
        return 1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        return 1;
    }

    LOG("Connected to server %s:%d\n", server_ip, SERVER_PORT);

    // Receive server's public keys
    unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];

    if (recv_all(sock, recv_kx_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
        perror("Failed to receive server ECDH public key");
        close(sock);
        return 1;
    }

    if (recv_all(sock, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES) != CRYPTO_PUBLICKEYBYTES) {
        perror("Failed to receive server Kyber public key");
        close(sock);
        return 1;
    }

    LOG("Received server public keys\n");

    // Generate client ECDH keypair
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sender_kx_sk[crypto_kx_SECRETKEYBYTES];
    if (crypto_kx_keypair(sender_kx_pk, sender_kx_sk) != 0) {
        fprintf(stderr, "Sender crypto_kx_keypair failed\n");
        close(sock);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    ecdhe_keypair_time = get_time_diff(start, end) * 1000;

    // Compute ECDH shared secret
    unsigned char cli_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char cli_tx[crypto_kx_SESSIONKEYBYTES];
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_kx_client_session_keys(cli_rx, cli_tx, sender_kx_pk, sender_kx_sk, recv_kx_pk) != 0) {
        fprintf(stderr, "ECDH client key derivation failed\n");
        close(sock);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    ecdhe_derive_time = get_time_diff(start, end) * 1000;

    unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared, cli_tx, crypto_kx_SESSIONKEYBYTES);

    // Kyber encapsulation
    unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char kyber_ss[CRYPTO_BYTES];
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_kem_enc(kyber_ct, kyber_ss, recv_kyber_pk) != 0) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        close(sock);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    kyber_encap_time = get_time_diff(start, end) * 1000;

    // Derive hybrid key
    unsigned char hybrid_key[HYBRID_KEY_BYTES];
    unsigned char input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(input, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    memcpy(input + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_generichash(hybrid_key, HYBRID_KEY_BYTES, input, sizeof(input), NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &end);
    key_derivation_time = get_time_diff(start, end) * 1000;

    // Encrypt message
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t message_len = strlen(MESSAGE);
    unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_secretbox_easy(ciphertext, (const unsigned char *)MESSAGE, message_len, nonce, hybrid_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    encryption_time = get_time_diff(start, end) * 1000;

    // Send client's data to server
    // Send sender's ECDH public key
    if (send_all(sock, sender_kx_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
        perror("Failed to send ECDH public key");
        close(sock);
        return 1;
    }

    // Send Kyber ciphertext
    if (send_all(sock, kyber_ct, CRYPTO_CIPHERTEXTBYTES) != CRYPTO_CIPHERTEXTBYTES) {
        perror("Failed to send Kyber ciphertext");
        close(sock);
        return 1;
    }

    // Send nonce
    if (send_all(sock, nonce, crypto_secretbox_NONCEBYTES) != crypto_secretbox_NONCEBYTES) {
        perror("Failed to send nonce");
        close(sock);
        return 1;
    }

    // Send ciphertext length (network byte order)
    uint32_t ciphertext_len_net = htonl(sizeof(ciphertext));
    if (send_all(sock, &ciphertext_len_net, sizeof(uint32_t)) != sizeof(uint32_t)) {
        perror("Failed to send ciphertext length");
        close(sock);
        return 1;
    }

    // Send ciphertext
    if (send_all(sock, ciphertext, sizeof(ciphertext)) != sizeof(ciphertext)) {
        perror("Failed to send ciphertext");
        close(sock);
        return 1;
    }

    LOG("Sent encrypted message to server\n");

    // Receive response from server
    int valread = recv(sock, buffer, sizeof(buffer), 0);
    if (valread > 0) {
        buffer[valread] = '\0';
        LOG("Server response: %s\n", buffer);
        printf("Server response: %s\n", buffer);
    }

    // Print timing results
    LOG("Timing Results:\n");
    LOG("ECDHE keypair generation: %.6f ms\n", ecdhe_keypair_time);
    LOG("ECDHE key derivation: %.6f ms\n", ecdhe_derive_time);
    LOG("Kyber encapsulation: %.6f ms\n", kyber_encap_time);
    LOG("Hybrid key derivation: %.6f ms\n", key_derivation_time);
    LOG("Encryption: %.6f ms\n", encryption_time);

    close(sock);
    LOG("Connection closed\n");

    return 0;
}