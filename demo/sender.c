#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "kyber/ref/api.h"
#include "kyber/ref/kem.h"
#include "static_kyber_keys.h"

#define HYBRID_KEY_BYTES 32   // 256-bit symmetric key
#define MESSAGE "Hello, this is a secret message!"

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

    // --- Use static receiver Kyber public key (same across all runs) ---
    unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];

    printf("Enter receiver ECDH public key (hex, 64 chars): ");
    for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) {
        unsigned int val;
        if (scanf("%2x", &val) != 1) {
            fprintf(stderr, "Invalid input for ECDH public key\n");
            return 1;
        }
        recv_kx_pk[i] = (unsigned char)val;
    }

    // Use static Kyber public key (no need to input)
    memcpy(recv_kyber_pk, SERVER_KYBER_PK, CRYPTO_PUBLICKEYBYTES);
    printf("Using static receiver Kyber public key\n");

    // Generate sender ECDH keypair
    unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sender_kx_sk[crypto_kx_SECRETKEYBYTES];
    if (crypto_kx_keypair(sender_kx_pk, sender_kx_sk) != 0) {
        fprintf(stderr, "Sender crypto_kx_keypair failed\
");
        return 1;
    }

    // Compute ECDH shared secret (client_tx)
    unsigned char cli_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char cli_tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(cli_rx, cli_tx,
                                     sender_kx_pk, sender_kx_sk,
                                     recv_kx_pk) != 0) {
        fprintf(stderr, "ECDH client key derivation failed\
");
        return 1;
    }
    unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared, cli_tx, crypto_kx_SESSIONKEYBYTES);

    // Kyber encapsulation
    unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char kyber_ss[CRYPTO_BYTES];
    if (crypto_kem_enc(kyber_ct, kyber_ss, recv_kyber_pk) != 0) {
        fprintf(stderr, "Kyber encapsulation failed\
");
        return 1;
    }

    // Derive hybrid key = hash(ecdh_shared || kyber_ss)
    unsigned char hybrid_key[HYBRID_KEY_BYTES];
    unsigned char input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(input, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    memcpy(input + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);
    crypto_generichash(hybrid_key, HYBRID_KEY_BYTES, input, sizeof(input), NULL, 0);

    print_hex("Sender ECDH shared", ecdh_shared, crypto_kx_SESSIONKEYBYTES);
    print_hex("Sender Kyber shared", kyber_ss, CRYPTO_BYTES);
    print_hex("Sender Hybrid key", hybrid_key, HYBRID_KEY_BYTES);

    // Encrypt message using hybrid key with crypto_secretbox_easy
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t message_len = sizeof(MESSAGE);
    unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];
    crypto_secretbox_easy(ciphertext, (const unsigned char *)MESSAGE, message_len, nonce, hybrid_key);

    // Output sender's public key, kyber ciphertext, nonce, and encrypted message as hex
    printf("\nSender ECDH public key (hex): ");
    for (size_t i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) printf("%02x", sender_kx_pk[i]);
    printf("\n");

    printf("Kyber ciphertext (hex): ");
    for (size_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", kyber_ct[i]);
    printf("\n");

    printf("Nonce (hex): ");
    for (size_t i = 0; i < crypto_secretbox_NONCEBYTES; i++) printf("%02x", nonce[i]);
    printf("\n");

    printf("Encrypted message (hex): ");
    for (size_t i = 0; i < sizeof(ciphertext); i++) printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}