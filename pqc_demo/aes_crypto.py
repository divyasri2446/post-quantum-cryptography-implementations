"""
aes_crypto.py
-------------
AES-256-GCM authenticated encryption.
Key (32 bytes) and nonce (12 bytes) both sourced from quantum_rng.
GCM mode gives both confidentiality AND integrity (built-in MAC tag).
"""

from Crypto.Cipher import AES
from quantum_rng import get_random_bytes


def aes_encrypt(plaintext: bytes, aes_key: bytes | None = None) -> dict:
    """
    Encrypt plaintext with AES-256-GCM.
    If aes_key is not provided, one is generated from quantum randomness.
    Returns key, nonce, ciphertext, and GCM tag — all as hex strings.
    """
    key = aes_key if aes_key is not None else get_random_bytes(32)  # 256-bit key
    nonce = get_random_bytes(12)   # 96-bit nonce (GCM standard)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "aes_key": key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def aes_decrypt(
    aes_key_hex: str,
    nonce_hex: str,
    ciphertext_hex: str,
    tag_hex: str,
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    Raises ValueError if the GCM tag fails (tampered/corrupted data).
    """
    key = bytes.fromhex(aes_key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext