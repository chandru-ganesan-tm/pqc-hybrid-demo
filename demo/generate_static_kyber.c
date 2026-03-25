// generate_static_kyber.c
// One-time utility to generate and output static Kyber keypair in C code format

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include "kyber/ref/api.h"
#include "kyber/ref/kem.h"

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    unsigned char kyber_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char kyber_sk[CRYPTO_SECRETKEYBYTES];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "Kyber keypair generation failed\n");
        return 1;
    }

    // Output public key in C array format
    printf("// Static server Kyber public key\n");
    printf("static const unsigned char SERVER_KYBER_PK[CRYPTO_PUBLICKEYBYTES] = {\n");
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        if (i % 16 == 0) printf("    ");
        printf("0x%02x", kyber_pk[i]);
        if (i < CRYPTO_PUBLICKEYBYTES - 1) printf(",");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n};\n\n");

    // Output private key in C array format
    printf("// Static server Kyber private key\n");
    printf("static const unsigned char SERVER_KYBER_SK[CRYPTO_SECRETKEYBYTES] = {\n");
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        if (i % 16 == 0) printf("    ");
        printf("0x%02x", kyber_sk[i]);
        if (i < CRYPTO_SECRETKEYBYTES - 1) printf(",");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n};\n");

    return 0;
}
