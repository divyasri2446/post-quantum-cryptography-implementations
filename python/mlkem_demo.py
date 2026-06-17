import oqs
import binascii

print("=" * 60)
print("       ML-KEM-768 POST-QUANTUM KEY EXCHANGE DEMO")
print("=" * 60)

with oqs.KeyEncapsulation("ML-KEM-768") as kem:

    print("\n[1] Generating Alice's Key Pair...")

    public_key = kem.generate_keypair()

    print("Public Key Size :", len(public_key), "bytes")

    print("\n[2] Bob Encapsulates Secret...")

    ciphertext, shared_secret_bob = kem.encap_secret(public_key)

    print("Ciphertext Size :", len(ciphertext), "bytes")
    print("Shared Secret Size :", len(shared_secret_bob), "bytes")

    print("\nShared Secret Preview (Bob):")
    print(binascii.hexlify(shared_secret_bob[:16]).decode())

    print("\n[3] Alice Decapsulates...")

    shared_secret_alice = kem.decap_secret(ciphertext)

    print("\nShared Secret Preview (Alice):")
    print(binascii.hexlify(shared_secret_alice[:16]).decode())

    print("\n[4] Verification...")

    if shared_secret_bob == shared_secret_alice:
        print("Shared Secret Match : TRUE")
        print("Quantum-Resistant Key Exchange Successful")
    else:
        print("Shared Secret Match : FALSE")

print("\nML-KEM-768 DEMO COMPLETED")