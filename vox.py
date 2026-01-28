#  Vox Encryption Module        v1.5
#  Documentation          jts.gg/vox
#  License         r2.jts.gg/license

import os
import hashlib
import hmac
import base64

SALT_LEN        = 32
TAG_LEN         = 32
MAC_KEY_LEN     = 32
KDF_ITERS       = 300_000
KDF_KEY_LEN     = 32
KEM_LEN         = 32

def encrypt(plaintext: str, passkey, asym: bool = False) -> bytes:

    pt_bytes = plaintext.encode("utf-8")

    if asym:
        enc, shared = _kem_encapsulate(passkey)
        ct = _vox_encrypt_bytes(pt_bytes, shared)
        return enc + ct

    else:
        return _vox_encrypt_bytes(pt_bytes, passkey.encode("utf-8"))


def decrypt(ciphertext: bytes, passkey, asym: bool = False) -> str:

    if asym:
        if len(ciphertext) < KEM_LEN + SALT_LEN + TAG_LEN:
            raise ValueError("Invalid asymmetric ciphertext")

        enc = ciphertext[:KEM_LEN]
        vox_ct = ciphertext[KEM_LEN:]

        shared = _kem_decapsulate(enc, passkey)
        pt = _vox_decrypt_bytes(vox_ct, shared)
        return pt.decode("utf-8")

    else:
        pt = _vox_decrypt_bytes(ciphertext, passkey.encode("utf-8"))
        return pt.decode("utf-8")


def _vox_encrypt_bytes(pt_bytes: bytes, passkey: bytes) -> bytes:

    salt = os.urandom(SALT_LEN)

    master_key = _kdf(passkey, salt)
    enc_stream = _derive_keystream(master_key, salt, len(pt_bytes), ctx=b"enc")

    ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, enc_stream))

    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")
    tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    return ct_bytes + salt + tag


def _vox_decrypt_bytes(ciphertext: bytes, passkey: bytes) -> bytes:

    if len(ciphertext) < SALT_LEN + TAG_LEN:
        raise ValueError("Invalid ciphertext")

    ct_bytes = ciphertext[:-(SALT_LEN + TAG_LEN)]
    salt = ciphertext[-(SALT_LEN + TAG_LEN):-TAG_LEN]
    tag = ciphertext[-TAG_LEN:]

    master_key = _kdf(passkey, salt)

    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")
    expected_tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Integrity check failed")

    enc_stream = _derive_keystream(master_key, salt, len(ct_bytes), ctx=b"enc")
    return bytes(a ^ b for a, b in zip(ct_bytes, enc_stream))


def keypair():

    sk = os.urandom(32)
    pk = hashlib.sha256(sk).digest()

    return (
        base64.b64encode(pk).decode("ascii"),
        base64.b64encode(sk).decode("ascii")
    )


def _kem_encapsulate(pk_b64: str):

    pk = base64.b64decode(pk_b64, validate=True)

    if len(pk) != 32:
        raise ValueError("Invalid public key length")

    r = os.urandom(32)
    mask = hashlib.sha256(pk).digest()

    enc = bytes(x ^ y for x, y in zip(r, mask))
    shared = hashlib.sha256(r + pk).digest()

    return enc, shared


def _kem_decapsulate(enc: bytes, sk_b64: str):

    sk = base64.b64decode(sk_b64, validate=True)

    if len(enc) != 32 or len(sk) != 32:
        raise ValueError("Invalid input length")

    pk = hashlib.sha256(sk).digest()
    mask = hashlib.sha256(pk).digest()

    r = bytes(x ^ y for x, y in zip(enc, mask))
    shared = hashlib.sha256(r + pk).digest()

    return shared


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
