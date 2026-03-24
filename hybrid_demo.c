// hybrid_demo.c
//
// Demonstrates a simple hybrid key exchange:
//   - Classical ECDHE (X25519 via libsodium)
//   - Post-quantum Kyber KEM (pq-crystals/kyber)
//   - Final hybrid key = H( ECDH_shared || Kyber_shared )
//
// Both "client" and "server" run inside one program for clarity.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

// Adjust include path to your Kyber repo clone
#include "kyber/ref/api.h"
#include "kyber/ref/kem.h"
#include "kyber/ref/fips202.h"
#include "kyber/ref/fips202.h"
#include "kyber/ref/indcpa.h"
#include "kyber/ref/cbd.h"
#include "kyber/ref/poly.h"
#include "kyber/ref/polyvec.h"

#define HYBRID_KEY_BYTES 32   // final symmetric key size (256-bit)
#define MESSAGE "Secret message!"

// Helper to print hex
static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
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

int main(void)
{

    print_keysizes();

    // ------------------------------------------------------------
    // Initialize libsodium (required before using crypto_kx_* APIs)
    // ------------------------------------------------------------
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    // ============================================================
    // 1. SERVER: generate classical ECDH keypair + Kyber KEM keypair
    // ============================================================

    // X25519 ECDH keypair
    unsigned char srv_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char srv_kx_sk[crypto_kx_SECRETKEYBYTES];
    if (crypto_kx_keypair(srv_kx_pk, srv_kx_sk) !=0) {
        fprintf(stderr, "server crypto_kx_keypair failed\n");
        return 1;
    }

    // Kyber KEM keypair
    unsigned char srv_kyber_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char srv_kyber_sk[CRYPTO_SECRETKEYBYTES];
    crypto_kem_keypair(srv_kyber_pk, srv_kyber_sk);
    if (crypto_kem_keypair(srv_kyber_pk, srv_kyber_sk) !=0) {
        fprintf(stderr, "server crypto_kem_keypair failed\n");
        return 1;
    }

    // ============================================================
    // 2. CLIENT: generate classical ECDH keypair
    // ============================================================

    unsigned char cli_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char cli_kx_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(cli_kx_pk, cli_kx_sk);
    if (crypto_kx_keypair(cli_kx_pk, cli_kx_sk) !=0) {
        fprintf(stderr, "client crypto_kx_keypair failed\n");
        return 1;
    }

    // In a real protocol:
    //   - Client receives srv_kx_pk and srv_kyber_pk from server
    //   - Server receives cli_kx_pk from client
    // Here we just use the variables directly.

    // ============================================================
    // 3. CLIENT: compute ECDH shared secret + Kyber encapsulation
    // ============================================================

    // crypto_kx_client_session_keys() produces two keys:
    //   rx = receive key (used here as ECDH shared secret)
    //   tx = send key   (unused in this demo)
    unsigned char cli_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char cli_tx[crypto_kx_SESSIONKEYBYTES];

    // In ECDHE-based key exchange, two separate symmetric keys are used for key exchange
    // cli-tx - client transmits encrypted data to server
    // svr-rx - server decrypts data received from client
    // svr-tx - server transmits encrypted data to client
    // cli-rx - client decrypts encrypted data received from server
    if (crypto_kx_client_session_keys(cli_rx, cli_tx,
                                      cli_kx_pk, cli_kx_sk,
                                      srv_kx_pk) != 0) {
        fprintf(stderr, "ECDH client key derivation failed\n");
        return 1;
    }

    unsigned char ecdh_shared_client[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared_client, cli_tx, crypto_kx_SESSIONKEYBYTES);\
    
    // Kyber Encapsulation: Process where the sender genetrates a random shared-secret and creates the cipher based on receiver's publickey (svr_kyber_pk)
    // Shared secret (kyber_ss_client) : Sender (client) generates a random shared-secret
    // Ciphertext (ct): Sender creates a ciphertext using reveiver (server) keyber publickey
    // Receiver (server) KEM publickey (svr_keyber_pk)

    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char kyber_ss_client[CRYPTO_BYTES];

    if (crypto_kem_enc(ct, kyber_ss_client, srv_kyber_pk) != 0) {
        fprintf(stderr, "Kyber encapsulation failed\n");
        return 1;
    }

    // ============================================================
    // 4. SERVER: compute ECDH shared secret + Kyber decapsulation
    // ============================================================

    unsigned char srv_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char srv_tx[crypto_kx_SESSIONKEYBYTES];

    if (crypto_kx_server_session_keys(srv_rx, srv_tx,
                                      srv_kx_pk, srv_kx_sk,
                                      cli_kx_pk) != 0) {
        fprintf(stderr, "ECDH server key derivation failed\n");
        return 1;
    }

    unsigned char ecdh_shared_server[crypto_kx_SESSIONKEYBYTES];
    memcpy(ecdh_shared_server, srv_rx, crypto_kx_SESSIONKEYBYTES);

    // Kyber Decapsulation: Process where the receiver (server) recovers the shared secret using it's kyber private (secret) key
    // Shared secret (kyber_ss_server) : Shared secret-key from sender (client); recovered via decapsulation
    // Ciphertext (ct): Received Ciphertext from sender (client) containing the shared-secret key
    // Server private-key (srv_kyber_sk): Server KEM private key

    //   - Server uses ct + it's secret key to recover the same shared secret
    unsigned char kyber_ss_server[CRYPTO_BYTES];
    if (crypto_kem_dec(kyber_ss_server, ct, srv_kyber_sk) != 0) {
        fprintf(stderr, "Kyber decapsulation failed\n");
        return 1;
    }

     // Now client_tx should equal server_rx, and client_rx should equal server_tx
    if (!(memcmp(cli_tx, srv_rx, crypto_kx_SESSIONKEYBYTES) == 0 &&
        memcmp(cli_rx, srv_tx, crypto_kx_SESSIONKEYBYTES) == 0)) {
        printf("Shared secrets do NOT match!\n");
    }

    // --- Debug: print raw shared secrets ---
    print_hex("ECDH client ss", ecdh_shared_client, crypto_kx_SESSIONKEYBYTES);
    print_hex("ECDH server ss", ecdh_shared_server, crypto_kx_SESSIONKEYBYTES);
    print_hex("Kyber client ss", kyber_ss_client, CRYPTO_BYTES);
    print_hex("Kyber server ss", kyber_ss_server, CRYPTO_BYTES);
    printf("\n");

    // ============================================================
    // 5. HYBRID KEY: hash(ECDH_shared || Kyber_shared)
    // ============================================================

    unsigned char hybrid_client[HYBRID_KEY_BYTES];
    unsigned char hybrid_server[HYBRID_KEY_BYTES];

    // Concatenate classical + PQ secrets
    unsigned char client_input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(client_input, ecdh_shared_client, crypto_kx_SESSIONKEYBYTES);
    memcpy(client_input + crypto_kx_SESSIONKEYBYTES,
           kyber_ss_client, CRYPTO_BYTES);

    unsigned char server_input[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
    memcpy(server_input, ecdh_shared_server, crypto_kx_SESSIONKEYBYTES);
    memcpy(server_input + crypto_kx_SESSIONKEYBYTES,
           kyber_ss_server, CRYPTO_BYTES);

    // BLAKE2b hash → final hybrid key
    crypto_generichash(hybrid_client, HYBRID_KEY_BYTES,
                       client_input, sizeof client_input,
                       NULL, 0);

    crypto_generichash(hybrid_server, HYBRID_KEY_BYTES,
                       server_input, sizeof server_input,
                       NULL, 0);

    // ============================================================
    // 6. Verify and display results
    // ============================================================

    if (sodium_memcmp(hybrid_client, hybrid_server, HYBRID_KEY_BYTES) != 0) {
        fprintf(stderr, "Hybrid keys DO NOT match!\n");
        return 1;
    }

    // print_hex("ECDH shared (client)", ecdh_shared_client, crypto_kx_SESSIONKEYBYTES);
    // print_hex("Kyber shared (client)", kyber_ss_client, CRYPTO_BYTES);
    // print_hex("Final HYBRID key", hybrid_client, HYBRID_KEY_BYTES);

    printf("Hybrid key established successfully.\n");
    
    // Encrypt message using client hybrid key with crypto_secretbox_easy
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t message_len = sizeof(MESSAGE);
    unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];
    crypto_secretbox_easy(ciphertext, (const unsigned char *)MESSAGE, message_len, nonce, hybrid_client);

    // Output sender's public key, kyber ciphertext, nonce, and encrypted message as hex
    printf("\nSender ECDH public key (hex): (%d bytes)", crypto_kx_PUBLICKEYBYTES);
    for (size_t i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) printf("%02x", cli_kx_pk[i]);
    printf("\n");

    printf("Kyber ciphertext (hex): (%d bytes)", CRYPTO_CIPHERTEXTBYTES);
    for (size_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]);
    printf("\n");

    printf("Nonce (hex): (%d bytes)", crypto_secretbox_NONCEBYTES);
    for (size_t i = 0; i < crypto_secretbox_NONCEBYTES; i++) printf("%02x", nonce[i]);
    printf("\n");

    printf("Encrypted message (hex): (%ld bytes)", sizeof(ciphertext));
    for (size_t i = 0; i < sizeof(ciphertext); i++) printf("%02x", ciphertext[i]);
    printf("\n");
    
    // Decrypt message
    unsigned char decrypted[1024];
    if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, hybrid_server) != 0) {
        fprintf(stderr, "Decryption failed\
");
        return 1;
    }

    printf("Decrypted message: %s\
", decrypted);
    printf("\n");
    
    return 0;

}