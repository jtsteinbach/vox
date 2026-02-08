# Vox Encryption Module v1.7.1

## Documentation and License
This module implements a misuse-resistant AEAD (Authenticated Encryption with Associated Data) using HMAC-SHA512 for PRF, PBKDF2-HMAC-SHA512 for key stretching, and HKDF-Expand (RFC 5869) for key separation. It is designed to provide confidentiality and authenticity of data in transit, nonce misuse resistance, and key separation.

Documentation: [jts.gg/vox](http://jts.gg/vox)  
License: [r2.jts.gg/license](http://r2.jts.gg/license)

## Security Properties
- AEAD confidentiality and authenticity
- Nonce misuse resistance (SIV)
- Key separation
- RNG failure resistance

## Misuse Bounds and Limits
- Confidentiality is preserved under arbitrary nonce reuse.
- Repeated encryption of identical plaintext with identical associated data reveals equality only.
- Authenticity is always preserved.
- Recommended maximum data encrypted per key: 2^40 bytes (1TB) - hard limit: 2^46 bytes (64TB).

## Comparison to Other AES Encryption
| Property | Vox Encryption Module | AES Encryption |
| --- | --- | --- |
| Key Size | 512 bits | 256 bits |
| Block Size | 512 bits | 128 bits |
| Misuse Resistance | High | Low |
| Speed | Slow | Fast |
| Security Claims | High | Medium |

## Usage Guide
To use this module, you need to have Python 3.6 or later installed on your system. You can install it using pip:
```bash
pip install vox-encryption
```
Once the module is installed, you can import and use its functions in your code like so:
```python
from vox_encryption import encrypt, decrypt

# Encrypt a message
ciphertext = encrypt("Hello, World", "mysecretpassword")
print(f"Ciphertext: {ciphertext}")

# Decrypt the message
plaintext = decrypt(ciphertext, "mysecretpassword")
print(f"Plaintext: {plaintext}")
```
Remember to replace `"Hello, World"` and `"mysecretpassword"` with your actual data and password. The encrypted ciphertext is a byte string that can be stored or transmitted securely. To decrypt it, you need the same password used for encryption. 

For more advanced usage, such as using symmetric key encryption (SKE) instead of AEAD, or encapsulating keys with public-key encryption (KEM), please refer to the module's documentation.
