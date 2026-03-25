#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "kyber/ref/api.h"
#include "kyber/ref/kem.h"
#include "static_kyber_keys.h"

#define HYBRID_KEY_BYTES 32   // 256-bit symmetric key

// Helper to print hex
static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static void print_keysizes()
{
    printf("key sizes:\n");

    if(KYBER_K == 2) 
        printf("Kyber variant: Kyber512\n");
    else if(KYBER_K == 3) 
    printf("Kyber variant: Kyber768\n");
    else if(KYBER_K == 4) 
        printf("Kyber variant: Kyber1024\n");


    printf("CRYPTO_PUBLICKEYBYTES (Kyber pubkey) = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES (kyber secret) = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_CIPHERTEXTBYTES (kyber ct) = %d\n", CRYPTO_CIPHERTEXTBYTES);
    printf("CRYPTO_BYTES (kyber ss) = %d\n", CRYPTO_BYTES);
    printf("HYBRID_KEY_BYTES (final symmetric key) = %d\n", HYBRID_KEY_BYTES);
    printf("NONCEBYTES = %d\n", crypto_secretbox_NONCEBYTES);
    printf("SESSIONKEYBYTES = %d\n\n", crypto_kx_SESSIONKEYBYTES);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\
");
        return 1;
    }

     print_keysizes();

    // Generate receiver ECDH keypair
    unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char recv_kx_sk[crypto_kx_SECRETKEYBYTES];
    if (crypto_kx_keypair(recv_kx_pk, recv_kx_sk) != 0) {
        fprintf(stderr, "Receiver crypto_kx_keypair failed\n");
        return 1;
    }

    // Use static receiver Kyber keypair (generated once, hardcoded)
    unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char recv_kyber_sk[CRYPTO_SECRETKEYBYTES];
    memcpy(recv_kyber_pk, SERVER_KYBER_PK, CRYPTO_PUBLICKEYBYTES);
    memcpy(recv_kyber_sk, SERVER_KYBER_SK, CRYPTO_SECRETKEYBYTES);

    // Output receiver public keys for sender to use
    printf("Receiver ECDH public key (hex): ");
    for (size_t i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) printf("%02x", recv_kx_pk[i]);
    printf("\n");

    printf("Receiver Kyber public key (hex): ");
    for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", recv_kyber_pk[i]);
    printf("\n");

    // Receive sender's ECDH public key
    unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
    printf("Enter sender ECDH public key (hex, 64 chars): ");
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) {
        unsigned int val;
        if (scanf("%2x", &val) != 1) {
            fprintf(stderr, "Invalid input for ECDH public key\n");
            return 1;
        }
        sender_kx_pk[i] = (unsigned char)val;
    }

    // Receive Kyber ciphertext
    unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
    printf("Enter Kyber ciphertext (hex, %d chars): ", CRYPTO_CIPHERTEXTBYTES * 2);
    for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
        unsigned int val;
        if (scanf("%2x", &val) != 1) {
            fprintf(stderr, "Invalid input for Kyber ciphertext\n");
            return 1;
        }
        kyber_ct[i] = (unsigned char)val;
    }

    // Receive nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    printf("Enter nonce (hex, %d chars): ", crypto_secretbox_NONCEBYTES * 2);
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
        unsigned int val;
        if (scanf("%2x", &val) != 1) {
            fprintf(stderr, "Invalid input for nonce\n");
            return 1;
        }
        nonce[i] = (unsigned char)val;
    }

    // Receive encrypted message (hex, continuous string)
    unsigned char ciphertext[1024];
    size_t ciphertext_len = 0;
    char hex_input[4096];
    printf("Enter encrypted message (hex, continuous string): ");
    if (scanf("%s", hex_input) != 1) {
        fprintf(stderr, "Invalid input for encrypted message\n");
        return 1;
    }
    
    // Parse hex string to bytes
    size_t hex_len = strlen(hex_input);
    if (hex_len % 2 != 0 || hex_len / 2 > sizeof(ciphertext)) {
        fprintf(stderr, "Invalid hex input length\n");
        return 1;
    }
    ciphertext_len = hex_len / 2;
    for (size_t i = 0; i < ciphertext_len; i++) {
        unsigned int val;
        sscanf(hex_input + (i * 2), "%2x", &val);
        ciphertext[i] = (unsigned char)val;
    }

    // Compute ECDH shared secret (server_rx)
    unsigned char srv_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char srv_tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_server_session_keys(srv_rx, srv_tx,
                                     recv_kx_pk, recv_kx_sk,
                                     sender_kx_pk) != 0) {
        fprintf(stderr, "ECDH server key derivation failed\
");
        return 1;
    }
    unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared, srv_rx, crypto_kx_SESSIONKEYBYTES);

    // Kyber decapsulation
    unsigned char kyber_ss[CRYPTO_BYTES];
    if (crypto_kem_dec(kyber_ss, kyber_ct, recv_kyber_sk) != 0) {
        fprintf(stderr, "Kyber decapsulation failed\
");
        return 1;
    }

    // Derive hybrid key = hash(ecdh_shared || kyber_ss)
    unsigned char hybrid_key[HYBRID_KEY_BYTES];
    unsigned char input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(input, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    memcpy(input + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);
    crypto_generichash(hybrid_key, HYBRID_KEY_BYTES, input, sizeof(input), NULL, 0);

    print_hex("Receiver ECDH shared", ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    print_hex("Receiver Kyber shared", kyber_ss, CRYPTO_BYTES);
    print_hex("Receiver Hybrid key", hybrid_key, HYBRID_KEY_BYTES);

    // Decrypt message
    unsigned char decrypted[1024];
    if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, hybrid_key) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted message: %s\n", decrypted);

    return 0;
}