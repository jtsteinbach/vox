# Vox Encryption Module (Uncrackable)

Reusing keys destroys security integrity!
Keys are also the same length as the encrypted data + formatted header and footer.
Each decryption checks for corrupted outputs.

# Usage:
import vox

encrypt(plaintext: str)

decrypt(ciphertext_b64: str, key_value: str)
