#  Vox Encryption Module        v1.4
#  Documentation          jts.gg/vox
#  License         r2.jts.gg/license

import os
import hashlib
import hmac

SALT_LEN        = 32
TAG_LEN         = 32
MAC_KEY_LEN     = 32
KDF_ITERS       = 300_000
KDF_KEY_LEN     = 32


def encrypt(plaintext: str, passkey: str) -> bytes:
    pt_bytes = plaintext.encode("utf-8")
    salt = os.urandom(SALT_LEN)

    master_key = _kdf(passkey.encode("utf-8"), salt)
    enc_stream = _derive_keystream(master_key, salt, len(pt_bytes), ctx=b"enc")

    ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, enc_stream))

    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")
    tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    return ct_bytes + salt + tag


def decrypt(ciphertext: bytes, passkey: str) -> str:
    if len(ciphertext) < SALT_LEN + TAG_LEN:
        raise ValueError("Invalid ciphertext")

    ct_bytes = ciphertext[:-(SALT_LEN + TAG_LEN)]
    salt = ciphertext[-(SALT_LEN + TAG_LEN):-TAG_LEN]
    tag = ciphertext[-TAG_LEN:]

    master_key = _kdf(passkey.encode("utf-8"), salt)

    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")
    expected_tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Integrity check failed (wrong passkey or tampered data)")

    enc_stream = _derive_keystream(master_key, salt, len(ct_bytes), ctx=b"enc")
    pt_bytes = bytes(a ^ b for a, b in zip(ct_bytes, enc_stream))

    return pt_bytes.decode("utf-8")


def _kdf(passkey: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        passkey,
        salt,
        KDF_ITERS,
        dklen=KDF_KEY_LEN
    )


def _derive_keystream(master_key: bytes, salt: bytes, length: int, ctx: bytes = b"") -> bytes:
    blocks = []
    current = hashlib.sha256(master_key + salt + ctx).digest()

    out_len = 0
    while out_len < length:
        blocks.append(current)
        out_len += len(current)
        current = hashlib.sha256(current).digest()

    return b"".join(blocks)[:length]
