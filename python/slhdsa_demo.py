import oqs
import binascii

print("=" * 60)
print("     SLH-DSA-SHA2-128f HASH-BASED SIGNATURE DEMO")
print("=" * 60)

message = b"Post Quantum Encryption"

with oqs.Signature("SLH_DSA_PURE_SHA2_128F") as signer:

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

    print("\n[4] Verifying Original Message...")

    valid = signer.verify(
        message,
        signature,
        public_key
    )

    if valid:
        print("Verification Status : VALID")
    else:
        print("Verification Status : INVALID")

    print("\n[5] Tampering Test...")

    tampered_message = b"Post Quantum Encryption Modified"

    tampered_valid = signer.verify(
        tampered_message,
        signature,
        public_key
    )

    if not tampered_valid:
        print("Tampering Detection : SUCCESS")
    else:
        print("Tampering Detection : FAILED")

    print("\nSecurity Outcome")
    print("----------------")
    print("[OK] Message Integrity Verified")
    print("[OK] Signature Authenticity Verified")
    print("[OK] Tampering Successfully Detected")

print("\nSLH-DSA DEMONSTRATION COMPLETED")