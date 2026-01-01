# Vox Encryption Module       v1.0
# Documentation         jts.gg/vox       
# License        r2.jts.gg/license

import os
import base64
import hashlib


def encrypt(plaintext: str, key_b64: str = ""):
    pt_bytes = plaintext.encode("utf-8")

    if key_b64 == "":
        key_bytes = os.urandom(len(pt_bytes))
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
    else:
        key_bytes = base64.b64decode(key_b64)

    if len(pt_bytes) != len(key_bytes):
        raise ValueError("Key length must match plaintext length")

    ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, key_bytes))
    ciphertext_b64 = base64.b64encode(ct_bytes).decode("ascii")

    uid = _key_uid(plaintext, key_b64)
    key_value = f"[Vox XOR Key]\n{key_b64}\n[{uid}]"

    return ciphertext_b64, key_value


def decrypt(ciphertext_b64: str, key_value: str) -> str:
    key_b64, key_uid = _parse_vox_key(key_value)

    ct_bytes = base64.b64decode(ciphertext_b64)
    key_bytes = base64.b64decode(key_b64)

    if len(ct_bytes) != len(key_bytes):
        raise ValueError("Key length must match ciphertext length")

    pt_bytes = bytes(a ^ b for a, b in zip(ct_bytes, key_bytes))
    plaintext = pt_bytes.decode("utf-8")

    if key_uid != _key_uid(plaintext, key_b64):
        raise ValueError("Failed Key UID Check - Decrypted data was corrupted!")

    return plaintext


def _key_uid(plaintext: str, key_b64: str) -> str:
    pt_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    key_hash = hashlib.sha256(key_b64.encode("utf-8")).hexdigest()
    combined = (pt_hash + key_hash).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()[:11]


def _parse_vox_key(s: str):
    header = "[Vox XOR Key]\n"
    if header not in s:
        raise ValueError("Missing [Vox XOR Key] header")

    after = s.split(header, 1)[1]
    lines = after.splitlines()
    i = len(lines) - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 0:
        raise ValueError("Missing UID line")

    uid_line = lines[i].strip()
    if not (uid_line.startswith("[") and uid_line.endswith("]")):
        raise ValueError("Last non-empty line is not a [UID] line")
    key_uid = uid_line[1:-1]
    key_b64 = "\n".join(lines[:i]).strip()

    if key_b64 == "":
        raise ValueError("Missing key value (base64)")

    return key_b64, key_uid
