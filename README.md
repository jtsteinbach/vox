# Vox Encryption Module v1.3

Vox is a password-based stream encryption library implemented in Python.
It derives a cryptographic keystream from a passkey using a KDF and SHA-256,
encrypts via XOR, and provides integrity using HMAC-SHA256.

---

## Security Model

### Key Derivation
- Passkeys are processed using PBKDF2-HMAC-SHA256
- 300,000 iterations
- 32-byte random salt per encryption
- Produces a fixed 256-bit master key

Purpose:
- Slow offline password guessing
- Prevent precomputation and rainbow tables
- Allow safe passkey reuse

---

### Keystream Generation
- SHA-256 hash-chain expansion
- Deterministic per `(passkey, salt)`
- Length exactly matches plaintext
- Context separation (`enc` / `mac`) ensures key independence

Purpose:
- Stream-cipher style encryption
- No keystream reuse
- No structural leakage

---

### Encryption
- Plaintext is XORed with the derived keystream
- Equivalent to a stream cipher under correct keystream usage

---

### Integrity & Authentication
- Encrypt-then-MAC using HMAC-SHA256
- MAC covers `(salt || ciphertext)`
- Constant-time verification on decrypt

Guarantees:
- Tampering is detected
- Wrong passkeys fail cleanly
- No silent corruption

---

## Threat Model

### Protects Against
- Passive ciphertext inspection
- Offline brute-force attacks (KDF-bounded)
- Ciphertext modification
- Bit-flipping attacks
- Keystream reuse

---

## What Vox Is
- Password-based stream encryption
- Library-friendly
- No stored secrets
- Salted, authenticated, KDF-hardened

---

## Comparison to AES-256-GCM

| Property | Vox v1.3 | AES-256-GCM |
|-------|---------|-------------|
| Security type | Computational | Computational |
| Password support | Yes (PBKDF2) | Yes (PBKDF2 / Argon2) |
| Integrity | HMAC-SHA256 | Built-in AEAD |
| Keystream reuse safety | Yes (salted) | Yes (nonce) |

Vox can be **cryptographically comparable** to AES-256 when used with a
high-entropy passkey.

---

## Usage

```python
from vox import encrypt, decrypt

ciphertext = encrypt("hello world", "my-strong-passkey")
plaintext = decrypt(ciphertext, "my-strong-passkey")
