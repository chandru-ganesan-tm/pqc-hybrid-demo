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
#define PORT 8080
#define BUFFER_SIZE 4096

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
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    struct timespec start, end;
    double ecdhe_keypair_time = 0, ecdhe_derive_time = 0, kyber_decap_time = 0, key_derivation_time = 0, decryption_time = 0;

    if (argc > 1 && (strcmp(argv[1], "--debug") == 0 || strcmp(argv[1], "-d") == 0)) {
        debug = 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        perror("setsockopt SO_REUSEADDR failed");
        return 1;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) != 0) {
        perror("setsockopt SO_REUSEPORT failed");
        return 1;
    }
#endif

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    // Listen with a larger accept queue for bursty load tests.
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen failed");
        return 1;
    }

    LOG("Server listening on port %d (ready for load testing)\n", PORT);

    while (1) {
        LOG("Waiting for client connection...\n");

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }

        LOG("Client connected from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Generate receiver ECDH keypair (fresh for each connection)
        clock_gettime(CLOCK_MONOTONIC, &start);
        unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char recv_kx_sk[crypto_kx_SECRETKEYBYTES];
        if (crypto_kx_keypair(recv_kx_pk, recv_kx_sk) != 0) {
            fprintf(stderr, "Receiver crypto_kx_keypair failed\n");
            close(new_socket);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        ecdhe_keypair_time = get_time_diff(start, end) * 1000;

        // Use static receiver Kyber keypair
        unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char recv_kyber_sk[CRYPTO_SECRETKEYBYTES];
        memcpy(recv_kyber_pk, SERVER_KYBER_PK, CRYPTO_PUBLICKEYBYTES);
        memcpy(recv_kyber_sk, SERVER_KYBER_SK, CRYPTO_SECRETKEYBYTES);

        // Send public keys to client
        if (send_all(new_socket, recv_kx_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
            perror("Failed to send ECDH public key");
            close(new_socket);
            continue;
        }
        if (send_all(new_socket, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES) != CRYPTO_PUBLICKEYBYTES) {
            perror("Failed to send Kyber public key");
            close(new_socket);
            continue;
        }

        // Receive client's data
        unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned char ciphertext[1024];
        size_t ciphertext_len;

        // Receive sender's ECDH public key
        if (recv_all(new_socket, sender_kx_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
            perror("Failed to receive sender ECDH public key");
            close(new_socket);
            continue;
        }

        // Receive Kyber ciphertext
        if (recv_all(new_socket, kyber_ct, CRYPTO_CIPHERTEXTBYTES) != CRYPTO_CIPHERTEXTBYTES) {
            perror("Failed to receive Kyber ciphertext");
            close(new_socket);
            continue;
        }

        // Receive nonce
        if (recv_all(new_socket, nonce, crypto_secretbox_NONCEBYTES) != crypto_secretbox_NONCEBYTES) {
            perror("Failed to receive nonce");
            close(new_socket);
            continue;
        }

        // Receive ciphertext length first
        uint32_t ciphertext_len_net;
        if (recv_all(new_socket, &ciphertext_len_net, sizeof(uint32_t)) != sizeof(uint32_t)) {
            perror("Failed to receive ciphertext length");
            close(new_socket);
            continue;
        }
        ciphertext_len = ntohl(ciphertext_len_net);

        if (ciphertext_len > sizeof(ciphertext)) {
            fprintf(stderr, "Ciphertext too large\n");
            close(new_socket);
            continue;
        }

        // Receive ciphertext
        if (recv_all(new_socket, ciphertext, ciphertext_len) != (ssize_t)ciphertext_len) {
            perror("Failed to receive ciphertext");
            close(new_socket);
            continue;
        }

        // Compute ECDH shared secret
        unsigned char srv_rx[crypto_kx_SESSIONKEYBYTES];
        unsigned char srv_tx[crypto_kx_SESSIONKEYBYTES];
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (crypto_kx_server_session_keys(srv_rx, srv_tx, recv_kx_pk, recv_kx_sk, sender_kx_pk) != 0) {
            fprintf(stderr, "ECDH server key derivation failed\n");
            close(new_socket);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        ecdhe_derive_time = get_time_diff(start, end) * 1000;

        unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES];
        memcpy(ecdh_shared, srv_rx, crypto_kx_SESSIONKEYBYTES);

        // Kyber decapsulation
        clock_gettime(CLOCK_MONOTONIC, &start);
        unsigned char kyber_ss[CRYPTO_BYTES];
        if (crypto_kem_dec(kyber_ss, kyber_ct, recv_kyber_sk) != 0) {
            fprintf(stderr, "Kyber decapsulation failed\n");
            close(new_socket);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        kyber_decap_time = get_time_diff(start, end) * 1000;

        // Derive hybrid key
        unsigned char hybrid_key[HYBRID_KEY_BYTES];
        unsigned char input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
        memcpy(input, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
        memcpy(input + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);
        clock_gettime(CLOCK_MONOTONIC, &start);
        crypto_generichash(hybrid_key, HYBRID_KEY_BYTES, input, sizeof(input), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        key_derivation_time = get_time_diff(start, end) * 1000;

        // Decrypt message
        unsigned char decrypted[1024];
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, hybrid_key) != 0) {
            fprintf(stderr, "Decryption failed\n");
            const char *error_msg = "DECRYPTION_FAILED";
            send(new_socket, error_msg, strlen(error_msg), 0);
            close(new_socket);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        decryption_time = get_time_diff(start, end) * 1000;

        LOG("Decrypted message: %s\n", decrypted);

        // Send success response
        const char *success_msg = "SUCCESS";
        send_all(new_socket, success_msg, strlen(success_msg));

        // Print timing results for this connection
        LOG("Timing Results (connection from %s:%d):\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        LOG("ECDHE keypair generation: %.6f ms\n", ecdhe_keypair_time);
        LOG("ECDHE key derivation: %.6f ms\n", ecdhe_derive_time);
        LOG("Kyber decapsulation: %.6f ms\n", kyber_decap_time);
        LOG("Hybrid key derivation: %.6f ms\n", key_derivation_time);
        LOG("Decryption: %.6f ms\n", decryption_time);

        close(new_socket);
        LOG("Connection closed\n");
    }

    close(server_fd);
    return 0;
}