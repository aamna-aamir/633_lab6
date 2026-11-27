#!/usr/bin/env python3
"""Pure LM hash implementation using TripleDES-with-equal-keys as a single-DES
substitute (cryptography lib dropped raw single DES, but DES-EDE3 with K1=K2=K3
mathematically collapses to plain single-DES encryption)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"KGS!@#$%"  # the fixed 8-byte LM magic string

def expand_key(k7: bytes) -> bytes:
    """Expand a 7-byte half-password into an 8-byte DES key (parity bits unset)."""
    s = k7
    key = [0]*8
    key[0] = s[0] >> 1
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
    key[7] = s[6] & 0x7F
    return bytes((b << 1) & 0xFF for b in key)

def des_encrypt_block(key8: bytes, block8: bytes) -> bytes:
    k3 = key8 * 3  # K1=K2=K3 -> 3DES-EDE collapses to single DES
    enc = Cipher(algorithms.TripleDES(k3), modes.ECB()).encryptor()
    return enc.update(block8) + enc.finalize()

def lm_hash(password: str) -> str:
    pw = password.upper().encode('ascii', errors='ignore')[:14]
    pw = pw.ljust(14, b'\x00')
    half1, half2 = pw[:7], pw[7:]
    k1 = expand_key(half1)
    k2 = expand_key(half2)
    h1 = des_encrypt_block(k1, MAGIC)
    h2 = des_encrypt_block(k2, MAGIC)
    return (h1 + h2).hex()

if __name__ == "__main__":
    # verify against the known test vector from asecuritysite.com itself
    test = lm_hash("hello")
    expected = "fda95fbeca288d44aad3b435b51404ee"
    print(f"self-test: hello -> {test}")
    print(f"expected:          {expected}")
    print("MATCH" if test == expected else "MISMATCH")
