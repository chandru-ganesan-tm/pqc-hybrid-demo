---
marp: true
title: Hybrid Cryptography Flow
paginate: false
---

# Hybrid Cryptography Flow (Easy View)

```mermaid
flowchart LR
    A[Sender]
    B[Generate ECDHE Key Pair]
    C[Generate Kyber Key Pair]
    D[Share Public Keys]
    E[ECDHE Shared Secret]
    F[Kyber Shared Secret]
    G[Combine Secrets with KDF\nSHA-256 or HKDF]
    H[Final Session Key]
    I[Encrypt Data with AES-GCM or ChaCha20-Poly1305]
    J[Receiver Decrypts and Verifies]

    A --> B
    A --> C
    B --> D
    C --> D
    D --> E
    D --> F
    E --> G
    F --> G
    G --> H
    H --> I
    I --> J
```

**Why hybrid?**
- ECDHE gives strong, fast classical security today.
- Kyber adds post-quantum protection against future quantum attacks.
- Combining both means an attacker must break both paths to recover the session key.
