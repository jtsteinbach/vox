#  Vox Encryption Module        v1.6
#  Documentation          jts.gg/vox
#  License         r2.jts.gg/license
#
#  this module implements a misuse-resistant AEAD using:
#    - HMAC-SHA256 (PRF)
#    - PBKDF2-HMAC-SHA256 (key stretching)
#    - HKDF-Expand (RFC 5869) (key separation)
#
#  security properties:
#    - AEAD confidentiality and authenticity
#    - nonce misuse resistance (SIV)
#    - key separation
#    - RNG failure resistance
#
#  misuse bounds and limits:
#  - confidentiality is preserved under arbitrary nonce reuse
#  - repeated encryption of identical plaintext with identical
#    associated data reveals equality only
#  - authenticity is always preserved
#  - recommended maximum data encrypted per key: 2^32 bytes

import os
import hashlib
import hmac
import base64
from typing import Optional

SALT_LEN        = 32        # synthetic nonce length (SIV)
TAG_LEN         = 32        # AEAD authentication tag length
KDF_ITERS       = 300_000   # PBKDF2 work factor
KDF_KEY_LEN     = 32        # master key length
KEM_LEN         = 32        # legacy asymmetric prefix length

# public API

def encrypt(
    plaintext: str,
    passkey: str,
    *,
    associated_data: bytes = b"",
    asym: bool = False
) -> bytes:
    # encrypts plaintext using AEAD
    # associated_data is authenticated but not encrypted

    pt = plaintext.encode("utf-8")

    if asym:
        enc, shared = _kem_encapsulate(passkey)
        ct = _aead_encrypt(pt, shared, associated_data)
        return enc + ct

    return _aead_encrypt(pt, passkey.encode(), associated_data)


def decrypt(
    ciphertext: bytes,
    passkey: str,
    *,
    associated_data: bytes = b"",
    asym: bool = False
) -> str:
    # verifies authenticity before decryption
    # decryption fails if authentication fails

    if asym:
        enc = ciphertext[:KEM_LEN]
        ct  = ciphertext[KEM_LEN:]
        shared = _kem_decapsulate(enc, passkey)
        pt = _aead_decrypt(ct, shared, associated_data)
        return pt.decode("utf-8")

    pt = _aead_decrypt(ciphertext, passkey.encode(), associated_data)
    return pt.decode("utf-8")

# AEAD core

def _aead_encrypt(
    plaintext: bytes,
    passkey: bytes,
    associated_data: bytes
) -> bytes:
    # SIV-style AEAD construction

    # a synthetic nonce is derived deterministically from the
    # plaintext and associated data using a MAC.

    # this provides nonce misuse resistance and removes reliance
    # on external randomness for security.

    master = _kdf(passkey)

    # key separation using HKDF-Expand
    # encryption and authentication keys are independent
    enc_key = _hkdf_expand(master, b"vox enc", 32)
    mac_key = _hkdf_expand(master, b"vox mac", 32)

    # synthetic nonce (SIV)
    salt = hmac.new(
        mac_key,
        associated_data + plaintext,
        hashlib.sha256
    ).digest()[:SALT_LEN]

    # encryption using PRF-based keystream
    stream = _derive_keystream(enc_key, salt, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))

    # authentication tag covers nonce, associated data, and ciphertext
    tag = hmac.new(
        mac_key,
        salt + associated_data + ciphertext,
        hashlib.sha256
    ).digest()

    return salt + ciphertext + tag

def _aead_decrypt(
    data: bytes,
    passkey: bytes,
    associated_data: bytes
) -> bytes:
    # verifies authentication prior to decryption
    # this prevents chosen-ciphertext attacks

    salt = data[:SALT_LEN]
    tag  = data[-TAG_LEN:]
    ct   = data[SALT_LEN:-TAG_LEN]

    master = _kdf(passkey)
    enc_key = _hkdf_expand(master, b"vox enc", 32)
    mac_key = _hkdf_expand(master, b"vox mac", 32)

    expected = hmac.new(
        mac_key,
        salt + associated_data + ct,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")

    stream = _derive_keystream(enc_key, salt, len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))

# key derivation

def _kdf(passkey: bytes) -> bytes:
    # PBKDF2-HMAC-SHA256 is used solely for key stretching

    # it is not used for password storage or verification.
    # the derived key is never stored or exposed.

    # the static salt is domain-separating and does not weaken
    # security under the defined threat model.

    return hashlib.pbkdf2_hmac(
        "sha256",
        passkey,
        b"vox-static-salt-SS7419",
        KDF_ITERS,
        dklen=KDF_KEY_LEN
    )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # HKDF-Expand as defined in RFC 5869
    # provides provable key separation under the PRF assumption

    out = b""
    t = b""
    counter = 1

    while len(out) < length:
        t = hmac.new(
            prk,
            t + info + bytes([counter]),
            hashlib.sha256
        ).digest()
        out += t
        counter += 1

    return out[:length]

# keystream generation

def _derive_keystream(
    key: bytes,
    nonce: bytes,
    length: int
) -> bytes:
    # PRF-based keystream generator
    # security reduces to the PRF security of HMAC-SHA256

    out = b""
    state = nonce

    while len(out) < length:
        state = hmac.new(key, state, hashlib.sha256).digest()
        out += state

    return out[:length]

# !!! legacy asymmetric (non-standard) !!!
# !!! does not provide forward secrecy and is excluded from security claims !!!

def keypair():
    sk = os.urandom(32)
    pk = hashlib.sha256(sk).digest()
    return (
        base64.b64encode(pk).decode(),
        base64.b64encode(sk).decode()
    )

def _kem_encapsulate(pk_b64: str):
    pk = base64.b64decode(pk_b64)
    r = os.urandom(32)
    mask = hashlib.sha256(pk).digest()
    enc = bytes(a ^ b for a, b in zip(r, mask))
    shared = hashlib.sha256(r + pk).digest()
    return enc, shared

def _kem_decapsulate(enc: bytes, sk_b64: str):
    sk = base64.b64decode(sk_b64)
    pk = hashlib.sha256(sk).digest()
    mask = hashlib.sha256(pk).digest()
    r = bytes(a ^ b for a, b in zip(enc, mask))
    return hashlib.sha256(r + pk).digest()
