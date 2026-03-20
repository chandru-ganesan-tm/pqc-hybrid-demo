#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include "kyber/ref/api.h" // TODO Pass ref dynamically
#include "kyber/ref/kem.h"

#define KYBER_K 2

// AES block size for ECB mode
#define AES_BLOCK_SIZE 16

// Pad message to multiple of AES block size (simple zero padding)
void pad_message(const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    *output_len = ((input_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    memcpy(output, input, input_len);
    if (*output_len > input_len) {
        memset(output + input_len, 0, *output_len - input_len);
    }
}

int main() {
    // Buffers for Kyber keys and ciphertext
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss_enc[CRYPTO_BYTES];  // Shared secret from encapsulation
    unsigned char ss_dec[CRYPTO_BYTES];  // Shared secret from decapsulation

    // 1. Generate Kyber keypair
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("Keypair generation failed\n");
        return 1;
    }
    printf("Kyber keypair generated.\n");

    // 2. Encapsulate shared secret (simulate sender)
    if (crypto_kem_enc(ct, ss_enc, pk) != 0) {
        printf("Encapsulation failed\n");
        return 1;
    }
    printf("Shared secret encapsulated.\n");

    // 3. Prepare message to encrypt
    const unsigned char message[] = "Hello PQC Hybrid Encryption!";
    size_t message_len = sizeof(message) - 1; // exclude null terminator

    // Pad message to AES block size
    unsigned char padded_message[256];
    size_t padded_len = 0;
    pad_message(message, message_len, padded_message, &padded_len);

    // 4. AES-256 ECB encrypt the message using shared secret as key
    unsigned char encrypted_message[256];
    AES_KEY aes_enc_key;

    // Use first 32 bytes of shared secret as AES-256 key
    if (AES_set_encrypt_key(ss_enc, 256, &aes_enc_key) < 0) {
        printf("AES set encrypt key failed\n");
        return 1;
    }

    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(padded_message + i, encrypted_message + i, &aes_enc_key, AES_ENCRYPT);
    }
    printf("Message encrypted with AES-256 ECB.\n");

    // --- Transmit ct and encrypted_message to recipient ---

    // 5. Decapsulate shared secret (simulate recipient)
    if (crypto_kem_dec(ss_dec, ct, sk) != 0) {
        printf("Decapsulation failed\n");
        return 1;
    }
    printf("Shared secret decapsulated.\n");

    // 6. AES-256 ECB decrypt the message using decapsulated shared secret
    unsigned char decrypted_message[256];
    AES_KEY aes_dec_key;

    if (AES_set_decrypt_key(ss_dec, 256, &aes_dec_key) < 0) {
        printf("AES set decrypt key failed\n");
        return 1;
    }

    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(encrypted_message + i, decrypted_message + i, &aes_dec_key, AES_DECRYPT);
    }

    // Null-terminate decrypted message at original length
    decrypted_message[message_len] = '\0';

    printf("Decrypted message: %s\n", decrypted_message);

    // Verify correctness
    if (memcmp(message, decrypted_message, message_len) == 0) {
        printf("Success: Decrypted message matches original.\n");
    } else {
        printf("Failure: Decrypted message does not match original.\n");
    }

    return 0;
}
