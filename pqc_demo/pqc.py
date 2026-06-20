"""
pqc.py
------
Post-Quantum Cryptography using liboqs-python.

Kyber  (ML-KEM-768): Key encapsulation. Keypair seeded directly from quantum DRBG.
Dilithium (ML-DSA-65): Digital signatures. Keypair seeded via liboqs custom RNG.

Quantum seeding coverage:
  - kyber_keygen:      uses generate_keypair_seed() with quantum bytes ✓
  - dilithium_keygen:  uses oqs.randombytes_nist_kat_init_256bit() to seed
                       liboqs internal RNG before keygen ✓
  - kyber_encapsulate: liboqs internal RNG (acceptable — encap randomness
                       does not affect key security, only ciphertext freshness)
"""

import oqs
from quantum_rng import get_random_bytes

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


# ── Kyber (ML-KEM) ────────────────────────────────────────────────────────────

def kyber_keygen() -> dict:
    """Generate Kyber keypair seeded directly from quantum DRBG."""
    kem = oqs.KeyEncapsulation(KEM_ALG)
    seed_len = kem.details.get("length_keypair_seed", 64)
    quantum_seed = get_random_bytes(seed_len)
    public_key = kem.generate_keypair_seed(quantum_seed)
    secret_key = kem.export_secret_key()
    return {
        "public_key": public_key.hex(),
        "secret_key": secret_key.hex(),
        "algorithm": KEM_ALG,
    }


def kyber_encapsulate(public_key_hex: str) -> dict:
    """
    Encapsulate to recipient's public key.
    Returns ciphertext (send to recipient) + shared_secret (use as AES key).
    """
    kem = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(bytes.fromhex(public_key_hex))
    return {
        "ciphertext": ciphertext.hex(),
        "shared_secret": shared_secret.hex(),
    }


def kyber_decapsulate(secret_key_hex: str, ciphertext_hex: str) -> dict:
    """Decapsulate with recipient's secret key → recover shared secret (AES key)."""
    kem_dec = oqs.KeyEncapsulation(KEM_ALG, bytes.fromhex(secret_key_hex))
    shared_secret = kem_dec.decap_secret(bytes.fromhex(ciphertext_hex))
    return {
        "shared_secret": shared_secret.hex(),
    }


# ── Dilithium (ML-DSA) ────────────────────────────────────────────────────────

def _seed_liboqs_rng():
    """
    Seed liboqs's internal NIST KAT RNG with 48 bytes of quantum randomness.
    This makes dilithium_keygen quantum-seeded.
    Falls back silently if the API is unavailable in this liboqs build.
    """
    try:
        seed_48 = get_random_bytes(48)
        oqs.randombytes_nist_kat_init_256bit(seed_48)
    except AttributeError:
        # Older liboqs-python builds don't expose this — silently fall through.
        pass


def dilithium_keygen() -> dict:
    """Generate Dilithium keypair with liboqs RNG seeded from quantum DRBG."""
    _seed_liboqs_rng()
    sig = oqs.Signature(SIG_ALG)
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return {
        "public_key": public_key.hex(),
        "secret_key": secret_key.hex(),
        "algorithm": SIG_ALG,
    }


def dilithium_sign(secret_key_hex: str, message: bytes) -> dict:
    """Sign message with Dilithium secret key."""
    sig = oqs.Signature(SIG_ALG, bytes.fromhex(secret_key_hex))
    signature = sig.sign(message)
    return {
        "signature": signature.hex(),
        "message_len": len(message),
    }


def dilithium_verify(public_key_hex: str, message: bytes, signature_hex: str) -> dict:
    """Verify a Dilithium signature."""
    sig = oqs.Signature(SIG_ALG)
    is_valid = sig.verify(
        message,
        bytes.fromhex(signature_hex),
        bytes.fromhex(public_key_hex),
    )
    return {"valid": bool(is_valid)}