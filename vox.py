#  vox encryption module        v1.5
#  documentation          jts.gg/vox
#  license         r2.jts.gg/license

import os
import hashlib
import hmac
import base64

SALT_LEN        = 32        # random salt added to each encryption
TAG_LEN         = 32        # integrity tag size (hmac-sha256)
MAC_KEY_LEN     = 32        # key length for hmac
KDF_ITERS       = 300_000   # pbkdf2 work factor
KDF_KEY_LEN     = 32        # derived master key length
KEM_LEN         = 32        # size of kem encapsulation


def encrypt(plaintext: str, passkey, asym: bool = False) -> bytes:
    # entry point for encryption

    # convert text to bytes
    pt_bytes = plaintext.encode("utf-8")

    if asym:
        # asymmetric mode:
        # derive a shared secret using the recipient public key
        enc, shared = _kem_encapsulate(passkey)

        # encrypt using the shared secret
        ct = _vox_encrypt_bytes(pt_bytes, shared)

        # prepend kem data so the receiver can recover the shared secret
        return enc + ct
    else:
        # symmetric mode:
        # encrypt directly using a password
        return _vox_encrypt_bytes(pt_bytes, passkey.encode("utf-8"))


def decrypt(ciphertext: bytes, passkey, asym: bool = False) -> str:
    # entry point for decryption

    if asym:
        # split kem data from the rest of the ciphertext
        enc = ciphertext[:KEM_LEN]
        vox_ct = ciphertext[KEM_LEN:]

        # recover shared secret using private key
        shared = _kem_decapsulate(enc, passkey)

        # decrypt symmetric portion
        pt = _vox_decrypt_bytes(vox_ct, shared)
        return pt.decode("utf-8")
    else:
        # symmetric decryption using password
        pt = _vox_decrypt_bytes(ciphertext, passkey.encode("utf-8"))
        return pt.decode("utf-8")


def _vox_encrypt_bytes(pt_bytes: bytes, passkey: bytes) -> bytes:
    # core symmetric encryption logic

    # generate random salt so identical messages never encrypt the same
    salt = os.urandom(SALT_LEN)

    # derive a master key from the passkey and salt
    master_key = _kdf(passkey, salt)

    # generate keystream for encryption
    enc_stream = _derive_keystream(master_key, salt, len(pt_bytes), ctx=b"enc")

    # xor plaintext with keystream to form ciphertext
    ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, enc_stream))

    # generate a separate keystream for authentication
    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")

    # compute integrity tag over salt + ciphertext
    tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    # output format: ciphertext || salt || tag
    return ct_bytes + salt + tag


def _vox_decrypt_bytes(ciphertext: bytes, passkey: bytes) -> bytes:
    # core symmetric decryption logic

    # split ciphertext into components
    ct_bytes = ciphertext[:-(SALT_LEN + TAG_LEN)]
    salt = ciphertext[-(SALT_LEN + TAG_LEN):-TAG_LEN]
    tag = ciphertext[-TAG_LEN:]

    # re-derive master key
    master_key = _kdf(passkey, salt)

    # re-derive mac key and verify integrity
    mac_key = _derive_keystream(master_key, salt, MAC_KEY_LEN, ctx=b"mac")
    expected_tag = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("integrity check failed")

    # regenerate keystream and xor to recover plaintext
    enc_stream = _derive_keystream(master_key, salt, len(ct_bytes), ctx=b"enc")
    return bytes(a ^ b for a, b in zip(ct_bytes, enc_stream))


def keypair():
    # generates a simple public/private keypair

    # private key is random
    sk = os.urandom(32)

    # public key is a hash of the private key
    pk = hashlib.sha256(sk).digest()

    # return both as base64 strings
    return (
        base64.b64encode(pk).decode("ascii"),
        base64.b64encode(sk).decode("ascii")
    )


def _kem_encapsulate(pk_b64: str):
    # creates a shared secret using a public key

    pk = base64.b64decode(pk_b64)

    # generate ephemeral secret
    r = os.urandom(32)

    # hide r using a hash of the public key
    mask = hashlib.sha256(pk).digest()
    enc = bytes(x ^ y for x, y in zip(r, mask))

    # derive shared secret from r and pk
    shared = hashlib.sha256(r + pk).digest()
    return enc, shared


def _kem_decapsulate(enc: bytes, sk_b64: str):
    # recovers the same shared secret using the private key

    sk = base64.b64decode(sk_b64)

    # recompute public key and mask
    pk = hashlib.sha256(sk).digest()
    mask = hashlib.sha256(pk).digest()

    # recover ephemeral secret
    r = bytes(x ^ y for x, y in zip(enc, mask))

    # derive shared secret
    shared = hashlib.sha256(r + pk).digest()
    return shared


def _kdf(passkey: bytes, salt: bytes) -> bytes:
    # slow password-based key derivation

    return hashlib.pbkdf2_hmac(
        "sha256",
        passkey,
        salt,
        KDF_ITERS,
        dklen=KDF_KEY_LEN
    )


def _derive_keystream(master_key: bytes, salt: bytes, length: int, ctx: bytes = b"") -> bytes:
    # expands the master key into a stream of pseudorandom bytes

    current = hashlib.sha256(master_key + salt + ctx).digest()
    out = b""

    # hash chaining until enough bytes are produced
    while len(out) < length:
        out += current
        current = hashlib.sha256(current).digest()

    return out[:length]
