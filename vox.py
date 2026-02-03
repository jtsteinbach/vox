#  Vox Encryption Module      v1.7.1
#  Documentation          jts.gg/vox
#  License         r2.jts.gg/license
#
#  this module implements a misuse-resistant AEAD using:
#    - HMAC-SHA512 (PRF)
#    - PBKDF2-HMAC-SHA512 (key stretching)
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
#  - recommended maximum data encrypted per key: 2^40 bytes (1TB) - hard limit: 2^46 bytes (64TB)

import os
import hashlib
import hmac
import base64

SALT_LEN        = 64        # synthetic nonce length (SIV)
TAG_LEN         = 64        # AEAD authentication tag length
KDF_ITERS       = 300_000   # PBKDF2 work factor
KDF_KEY_LEN     = 64        # master key length
KEM_LEN         = 64        # legacy asymmetric prefix length

# internal context cache
# ensures PBKDF2 is executed once per key lifecycle

_CTX_CACHE = {}

# key setup context

class VoxContext:
    # holds stretched and separated keys

    def __init__(self, passkey: bytes):
        master = _kdf(passkey)

        self.enc_key = _hkdf_expand(master, b"vox enc", 64)
        self.mac_key = _hkdf_expand(master, b"vox mac", 64)

# internal helper

def _get_context(passkey: bytes) -> VoxContext:
    ctx = _CTX_CACHE.get(passkey)
    if ctx is None:
        ctx = VoxContext(passkey)
        _CTX_CACHE[passkey] = ctx
    return ctx

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
        ctx = _get_context(shared)
        ct = _aead_encrypt(ctx, pt, associated_data)
        return enc + ct

    ctx = _get_context(passkey.encode())
    return _aead_encrypt(ctx, pt, associated_data)


def decrypt(
    ciphertext: bytes,
    passkey: str,
    *,
    associated_data: bytes = b"",
    asym: bool = False
) -> str:
    # verifies authenticity before decryption

    if asym:
        enc = ciphertext[:KEM_LEN]
        ct  = ciphertext[KEM_LEN:]
        shared = _kem_decapsulate(enc, passkey)
        ctx = _get_context(shared)
        pt = _aead_decrypt(ctx, ct, associated_data)
        return pt.decode("utf-8")

    ctx = _get_context(passkey.encode())
    pt = _aead_decrypt(ctx, ciphertext, associated_data)
    return pt.decode("utf-8")

# AEAD core

def _aead_encrypt(
    ctx: VoxContext,
    plaintext: bytes,
    associated_data: bytes
) -> bytes:
    # SIV-style AEAD construction

    salt = hmac.new(
        ctx.mac_key,
        associated_data + plaintext,
        hashlib.sha512
    ).digest()[:SALT_LEN]

    stream = _derive_keystream(ctx.enc_key, salt, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))

    tag = hmac.new(
        ctx.mac_key,
        salt + associated_data + ciphertext,
        hashlib.sha512
    ).digest()

    return salt + ciphertext + tag


def _aead_decrypt(
    ctx: VoxContext,
    data: bytes,
    associated_data: bytes
) -> bytes:
    # verifies authentication prior to decryption

    salt = data[:SALT_LEN]
    tag  = data[-TAG_LEN:]
    ct   = data[SALT_LEN:-TAG_LEN]

    expected = hmac.new(
        ctx.mac_key,
        salt + associated_data + ct,
        hashlib.sha512
    ).digest()

    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")

    stream = _derive_keystream(ctx.enc_key, salt, len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))

# key derivation

def _kdf(passkey: bytes) -> bytes:
    # PBKDF2-HMAC-SHA512 is used solely for key stretching

    return hashlib.pbkdf2_hmac(
        "sha512",
        passkey,
        b"vox-static-salt-SS7419",
        KDF_ITERS,
        dklen=KDF_KEY_LEN
    )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # HKDF-Expand as defined in RFC 5869

    out = b""
    t = b""
    counter = 1

    while len(out) < length:
        t = hmac.new(
            prk,
            t + info + bytes([counter]),
            hashlib.sha512
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
    # PRF keystream generator

    out = bytearray()
    counter = 0

    while len(out) < length:
        block = hmac.new(
            key,
            nonce + counter.to_bytes(5, "big"),
            hashlib.sha512
        ).digest()
        out.extend(block)
        counter += 1

    return bytes(out[:length])

# legacy asymmetric (non-standard)
# does not provide forward secrecy and is excluded from security claims

def keypair():
    sk = os.urandom(64)
    pk = hashlib.sha512(sk).digest()
    return (
        base64.b64encode(pk).decode(),
        base64.b64encode(sk).decode()
    )


def _kem_encapsulate(pk_b64: str):
    pk = base64.b64decode(pk_b64)
    r = os.urandom(64)
    mask = hashlib.sha512(pk).digest()
    enc = bytes(a ^ b for a, b in zip(r, mask))
    shared = hashlib.sha512(r + pk).digest()
    return enc, shared


def _kem_decapsulate(enc: bytes, sk_b64: str):
    sk = base64.b64decode(sk_b64)
    pk = hashlib.sha512(sk).digest()
    mask = hashlib.sha512(pk).digest()
    r = bytes(a ^ b for a, b in zip(enc, mask))
    return hashlib.sha512(r + pk).digest()
