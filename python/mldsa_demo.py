import oqs
import binascii
print("=" * 60)
print("      ML-DSA-65 POST-QUANTUM DIGITAL SIGNATURE DEMO")
print("=" * 60)
message = b"Post Quantum Encryption"
with oqs.Signature("ML-DSA-65") as signer:
    print("\n[1] Generating Key Pair...")
    public_key = signer.generate_keypair()
    print("Public Key Size :", len(public_key), "bytes")
    print("\n[2] Message Creation...")
    print("Message :", message.decode())
    print("\n[3] Signing Message...")
    signature = signer.sign(message)
    print("Signature Size :", len(signature), "bytes")
    print("\nSignature Preview:")
    print(binascii.hexlify(signature[:16]).decode())
    print("\n[4] Verifying Signature...")
    is_valid = signer.verify(
        message,
        signature,
        public_key
    )
    if is_valid:
        print("Verification Status : VALID")
    else:
        print("Verification Status : INVALID")
    print("\nSecurity Outcome")
    print("----------------")
    if is_valid:
        print("[OK] Message Integrity Verified")
        print("[OK] Signature Authenticity Verified")
        print("[OK] Quantum-Resistant Signature Valid")
    else:
        print("[FAIL] Signature Verification Failed")
print("\nML-DSA-65 DEMONSTRATION COMPLETED")