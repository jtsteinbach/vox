#  Vox Encryption Module           jts.gg/vox
#  License                  r2.jts.gg/license

from __future__ import annotations

import os
import base64
import hashlib
import struct
from typing import Tuple

__all__ = ["encrypt", "decrypt", "keypair"]
__version__ = "1.2.0"

VOX_XOR_HEADER = "[Vox XOR Key]\n"
VOX_MCE_HEADER = "[Vox MCE Package]\n"
VOX_MCE_PRIV_HEADER = "[Vox MCE Private Key]\n"
VOX_MCE_PUB_HEADER = "[Vox MCE Public Key]\n"

VOX_SEALED_MAGIC = b"VOX1"


def encrypt(plaintext: str, key_b64: str = "", asymmetric: bool = False):
    """
    Encrypt plaintext and return a sealed base64 blob.

    Returns:
      - Symmetric: sealed_b64
      - Asymmetric:
          - if key_b64 == "": (pub_key_text, priv_key_text, sealed_b64)
          - else: sealed_b64
    """
    pt_bytes = plaintext.encode("utf-8")
    if not asymmetric:
        return _encrypt_symmetric(plaintext, pt_bytes, key_b64)
    return _encrypt_asymmetric(plaintext, pt_bytes, key_b64)


def decrypt(sealed_b64: str, private_key_b64: str = "") -> str:
    """
    Decrypt a sealed blob produced by encrypt().
    private_key_b64 is required only for asymmetric packets.
    """
    ciphertext_b64, key_packet = _unpack_sealed(sealed_b64)

    if VOX_XOR_HEADER in key_packet:
        return _decrypt_symmetric(ciphertext_b64, key_packet)

    if VOX_MCE_HEADER in key_packet:
        return _decrypt_asymmetric(ciphertext_b64, key_packet, private_key_b64)

    raise ValueError("Unknown key packet format (missing Vox headers).")


def keypair() -> Tuple[str, str]:
    """
    Generate a Classic McEliece KEM keypair and return headered key strings.
    Requires: pip install pqcrypto
    """
    try:
        from pqcrypto.kem.mceliece8192128 import generate_keypair
    except Exception as e:
        raise ImportError("pqcrypto not installed. Install with: pip install pqcrypto") from e

    pk, sk = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    sk_b64 = base64.b64encode(sk).decode("ascii")

    pub_text = f"{VOX_MCE_PUB_HEADER}{pk_b64}"
    priv_text = f"{VOX_MCE_PRIV_HEADER}{sk_b64}"
    return pub_text, priv_text


def _encrypt_symmetric(plaintext: str, pt_bytes: bytes, key_b64: str) -> str:
    if key_b64 == "":
        key_bytes = os.urandom(len(pt_bytes))
        key_b64_used = base64.b64encode(key_bytes).decode("ascii")
    else:
        key_b64_used = _extract_xor_key_b64(key_b64)
        key_bytes = base64.b64decode(key_b64_used)

    if len(pt_bytes) != len(key_bytes):
        raise ValueError("Key length must match plaintext length")

    ct_bytes = _xor_bytes(pt_bytes, key_bytes)
    ciphertext_b64 = base64.b64encode(ct_bytes).decode("ascii")

    uid = _key_uid(plaintext, key_b64_used)
    key_packet = f"{VOX_XOR_HEADER}{key_b64_used}\n[{uid}]"

    return _pack_sealed(ciphertext_b64, key_packet)


def _decrypt_symmetric(ciphertext_b64: str, key_packet: str) -> str:
    key_b64, expected_uid = _parse_vox_xor_key(key_packet)

    ct_bytes = base64.b64decode(ciphertext_b64)
    key_bytes = base64.b64decode(key_b64)

    if len(ct_bytes) != len(key_bytes):
        raise ValueError("Key length must match ciphertext length")

    pt_bytes = _xor_bytes(ct_bytes, key_bytes)
    plaintext = pt_bytes.decode("utf-8")

    if expected_uid != _key_uid(plaintext, key_b64):
        raise ValueError("Failed Key UID Check - Decrypted data was corrupted!")

    return plaintext


def _encrypt_asymmetric(plaintext: str, pt_bytes: bytes, key_b64: str):
    generated_keys = False

    if key_b64 == "":
        generated_keys = True
        pub_text, priv_text = keypair()
        recipient_pub_raw_b64 = _extract_mce_key_b64(pub_text, expect="pub")
    else:
        recipient_pub_raw_b64 = _extract_mce_key_b64(key_b64, expect="pub")

    vox_key = os.urandom(len(pt_bytes))
    ct_bytes = _xor_bytes(pt_bytes, vox_key)
    ciphertext_b64 = base64.b64encode(ct_bytes).decode("ascii")

    kem_ct, ss = _mce_encapsulate(base64.b64decode(recipient_pub_raw_b64))

    stream = _sha256_stream(ss, len(vox_key))
    wrapped_vox_key = _xor_bytes(vox_key, stream)

    vox_key_b64 = base64.b64encode(vox_key).decode("ascii")
    uid = _key_uid(plaintext, vox_key_b64)

    key_packet = (
        f"{VOX_MCE_HEADER}"
        f"{base64.b64encode(kem_ct).decode('ascii')}\n"
        f"{base64.b64encode(wrapped_vox_key).decode('ascii')}\n"
        f"[{uid}]"
    )

    sealed_b64 = _pack_sealed(ciphertext_b64, key_packet)

    if generated_keys:
        return pub_text, priv_text, sealed_b64
    return sealed_b64


def _decrypt_asymmetric(ciphertext_b64: str, key_packet: str, private_key_b64: str) -> str:
    if private_key_b64 == "":
        raise ValueError("Missing private_key_b64 for McEliece decryption.")

    priv_raw_b64 = _extract_mce_key_b64(private_key_b64, expect="priv")

    kem_ct_b64, wrapped_vox_key_b64, expected_uid = _parse_vox_mce_bundle(key_packet)

    kem_ct = base64.b64decode(kem_ct_b64)
    wrapped_vox_key = base64.b64decode(wrapped_vox_key_b64)

    ss = _mce_decapsulate(base64.b64decode(priv_raw_b64), kem_ct)

    stream = _sha256_stream(ss, len(wrapped_vox_key))
    vox_key = _xor_bytes(wrapped_vox_key, stream)

    ct_bytes = base64.b64decode(ciphertext_b64)
    if len(ct_bytes) != len(vox_key):
        raise ValueError("Key length must match ciphertext length")

    pt_bytes = _xor_bytes(ct_bytes, vox_key)
    plaintext = pt_bytes.decode("utf-8")

    vox_key_b64 = base64.b64encode(vox_key).decode("ascii")
    if expected_uid != _key_uid(plaintext, vox_key_b64):
        raise ValueError("Failed Key UID Check - Decrypted data was corrupted!")

    return plaintext


def _pack_sealed(ciphertext_b64: str, key_packet: str) -> str:
    ct = ciphertext_b64.encode("utf-8")
    kp = key_packet.encode("utf-8")

    blob = (
        VOX_SEALED_MAGIC
        + struct.pack(">I", len(ct))
        + struct.pack(">I", len(kp))
        + ct
        + kp
    )
    return base64.b64encode(blob).decode("ascii")


def _unpack_sealed(sealed_b64: str) -> Tuple[str, str]:
    blob = base64.b64decode(sealed_b64)

    if len(blob) < 12 or blob[:4] != VOX_SEALED_MAGIC:
        raise ValueError("Invalid sealed message (bad magic/header)")

    ct_len = struct.unpack(">I", blob[4:8])[0]
    kp_len = struct.unpack(">I", blob[8:12])[0]

    start = 12
    end_ct = start + ct_len
    end_kp = end_ct + kp_len

    if end_kp != len(blob):
        raise ValueError("Invalid sealed message (length mismatch)")

    ciphertext_b64 = blob[start:end_ct].decode("utf-8")
    key_packet = blob[end_ct:end_kp].decode("utf-8")
    return ciphertext_b64, key_packet


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _key_uid(plaintext: str, key_b64: str) -> str:
    pt_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    key_hash = hashlib.sha256(key_b64.encode("utf-8")).hexdigest()
    combined = (pt_hash + key_hash).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()[:11]


def _parse_vox_xor_key(s: str) -> Tuple[str, str]:
    if VOX_XOR_HEADER not in s:
        raise ValueError("Missing [Vox XOR Key] header")

    after = s.split(VOX_XOR_HEADER, 1)[1]
    lines = after.splitlines()

    i = len(lines) - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 0:
        raise ValueError("Missing UID line")

    uid_line = lines[i].strip()
    if not (uid_line.startswith("[") and uid_line.endswith("]")):
        raise ValueError("Last non-empty line is not a [UID] line")

    uid = uid_line[1:-1]
    key_b64 = "\n".join(lines[:i]).strip()

    if key_b64 == "":
        raise ValueError("Missing key value (base64)")

    return key_b64, uid


def _parse_vox_mce_bundle(s: str) -> Tuple[str, str, str]:
    if VOX_MCE_HEADER not in s:
        raise ValueError("Missing [Vox MCE Package] header")

    after = s.split(VOX_MCE_HEADER, 1)[1]
    lines = after.splitlines()

    i = len(lines) - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 2:
        raise ValueError("Bundle missing fields")

    uid_line = lines[i].strip()
    if not (uid_line.startswith("[") and uid_line.endswith("]")):
        raise ValueError("Last non-empty line is not a [UID] line")

    uid = uid_line[1:-1]
    core = [ln.strip() for ln in lines[:i] if ln.strip() != ""]
    if len(core) < 2:
        raise ValueError("Bundle missing kem_ct or wrapped key")

    return core[0], core[1], uid


def _extract_xor_key_b64(s: str) -> str:
    s = s.strip()
    if s.startswith(VOX_XOR_HEADER):
        key_b64, _uid = _parse_vox_xor_key(s)
        return key_b64.strip()
    return s


def _extract_mce_key_b64(s: str, expect: str) -> str:
    s = s.strip()

    if expect == "pub" and s.startswith(VOX_MCE_PUB_HEADER):
        return s.split(VOX_MCE_PUB_HEADER, 1)[1].strip()

    if expect == "priv" and s.startswith(VOX_MCE_PRIV_HEADER):
        return s.split(VOX_MCE_PRIV_HEADER, 1)[1].strip()

    if s.startswith(VOX_MCE_PUB_HEADER) or s.startswith(VOX_MCE_PRIV_HEADER):
        raise ValueError(f"Wrong key type provided (expected {expect}).")

    return s


def _sha256_stream(seed: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        ctr = counter.to_bytes(8, "big")
        out.extend(hashlib.sha256(seed + ctr).digest())
        counter += 1
    return bytes(out[:nbytes])


def _mce_encapsulate(public_key: bytes):
    try:
        from pqcrypto.kem.mceliece8192128 import encrypt as encap
    except Exception as e:
        raise ImportError("pqcrypto not installed. Install with: pip install pqcrypto") from e
    return encap(public_key)


def _mce_decapsulate(private_key: bytes, kem_ct: bytes):
    try:
        from pqcrypto.kem.mceliece8192128 import decrypt as decap
    except Exception as e:
        raise ImportError("pqcrypto not installed. Install with: pip install pqcrypto") from e
    return decap(private_key, kem_ct)
