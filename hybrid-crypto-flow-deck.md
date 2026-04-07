---
marp: true
title: Hybrid Cryptography Flow
description: ECDH + Kyber hybrid key exchange and encryption flow
paginate: true
---

# Hybrid Cryptography: Why This Design?

## Goal
Use two independent key-agreement paths, then combine them into one session key.

## In this project
- Classical path: libsodium ECDH via `crypto_kx_*`
- Post-quantum path: Kyber KEM via `crypto_kem_enc/dec`
- Key combiner: `crypto_generichash` over `(ecdh_shared || kyber_ss)`
- Data protection: `crypto_secretbox_easy` (authenticated encryption)

## Security intuition
If one path weakens, the other still protects the final key derivation.

---

# End-to-End Flow (Sender -> Receiver)

```mermaid
flowchart LR
    R1[Receiver starts]
    R2[Generate ECDH keypair]
    R3[Load static Kyber keypair]
    S1[Sender starts]
    S2[Read receiver ECDH public key]
    S3[Load receiver static Kyber public key]

    E1[Sender ECDH shared secret]
    K1[Sender Kyber encapsulation\nct + kyber_ss]
    H1[Sender hybrid key\nH(ecdh || kyber_ss)]
    C1[Encrypt message with secretbox]

    TX[Transmit:\nsender ECDH pubkey + Kyber ct + nonce + ciphertext]

    E2[Receiver ECDH shared secret]
    K2[Receiver Kyber decapsulation\nkyber_ss]
    H2[Receiver hybrid key\nH(ecdh || kyber_ss)]
    D1[Decrypt + verify]

    R1 --> R2 --> R3
    S1 --> S2 --> S3
    S2 --> E1
    S3 --> K1
    E1 --> H1
    K1 --> H1 --> C1 --> TX
    TX --> E2
    TX --> K2
    E2 --> H2
    K2 --> H2 --> D1
```

---

# Mapping To Your Code

## Sender side
- ECDH keypair and shared secret: `crypto_kx_keypair`, `crypto_kx_client_session_keys`
- Kyber encapsulation: `crypto_kem_enc`
- Hybrid key derivation: `crypto_generichash`
- Encryption: `crypto_secretbox_easy`
- Output fields: sender ECDH public key, Kyber ciphertext, nonce, encrypted message

## Receiver side
- ECDH keypair and shared secret: `crypto_kx_keypair`, `crypto_kx_server_session_keys`
- Kyber decapsulation: `crypto_kem_dec`
- Same hybrid derivation: `crypto_generichash`
- Decryption: `crypto_secretbox_open_easy`

## Presenter notes (simple)
- "Both sides should print identical hybrid keys before decrypting."
- "Kyber ciphertext is not the message ciphertext; it transports the PQ shared secret."
- "Final confidentiality and integrity come from secretbox under the hybrid-derived key."
