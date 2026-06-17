#include <oqs/oqs.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>

using namespace std;

void print_separator() {
    cout << "\n============================================================\n";
}

void print_hex_preview(const vector<uint8_t>& data, size_t bytes = 16) {
    for (size_t i = 0; i < min(bytes, data.size()); i++) {
        cout << hex << uppercase << setw(2) << setfill('0')
             << static_cast<int>(data[i]) << " ";
    }
    cout << dec << "\n";
}

int main() {

    print_separator();
    cout << "        ML-KEM-768 POST-QUANTUM KEY EXCHANGE DEMO\n";
    print_separator();

    cout << "\nAlgorithm Information\n";
    cout << "---------------------\n";
    cout << "Algorithm      : ML-KEM-768\n";
    cout << "NIST Standard  : FIPS 203\n";
    cout << "Security Basis : Module Learning With Errors (MLWE)\n";
    cout << "Security Level : NIST Category 3\n";

    cout << "\n[1] Initializing ML-KEM-768...\n";

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == nullptr) {
        cerr << "ERROR: ML-KEM-768 not available.\n";
        return 1;
    }

    cout << "Status : SUCCESS\n";

    vector<uint8_t> public_key(kem->length_public_key);
    vector<uint8_t> secret_key(kem->length_secret_key);

    vector<uint8_t> ciphertext(kem->length_ciphertext);

    vector<uint8_t> shared_secret_enc(kem->length_shared_secret);
    vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

    cout << "\n[2] Generating Key Pair...\n";

    if (OQS_KEM_keypair(
            kem,
            public_key.data(),
            secret_key.data()) != OQS_SUCCESS) {

        cerr << "Key generation failed.\n";
        return 1;
    }

    cout << "Public Key Size : "
         << kem->length_public_key
         << " bytes\n";

    cout << "Secret Key Size : "
         << kem->length_secret_key
         << " bytes\n";

    cout << "Status          : SUCCESS\n";

    cout << "\n[3] Encapsulation Phase...\n";

    if (OQS_KEM_encaps(
            kem,
            ciphertext.data(),
            shared_secret_enc.data(),
            public_key.data()) != OQS_SUCCESS) {

        cerr << "Encapsulation failed.\n";
        return 1;
    }

    cout << "Ciphertext Size : "
         << kem->length_ciphertext
         << " bytes\n";

    cout << "Shared Secret Size : "
         << kem->length_shared_secret
         << " bytes\n";

    cout << "Status             : SUCCESS\n";

    cout << "\nShared Secret Preview (Bob):\n";
    print_hex_preview(shared_secret_enc);

    cout << "\n[4] Decapsulation Phase...\n";

    if (OQS_KEM_decaps(
            kem,
            shared_secret_dec.data(),
            ciphertext.data(),
            secret_key.data()) != OQS_SUCCESS) {

        cerr << "Decapsulation failed.\n";
        return 1;
    }

    cout << "Status : SUCCESS\n";

    cout << "\nShared Secret Preview (Alice):\n";
    print_hex_preview(shared_secret_dec);

    cout << "\n[5] Verification...\n";

    bool match =
        memcmp(shared_secret_enc.data(),
               shared_secret_dec.data(),
               kem->length_shared_secret) == 0;

    if (match)
        cout << "Shared Secret Match : TRUE\n";
    else
        cout << "Shared Secret Match : FALSE\n";

    cout << "\nSecurity Outcome\n";
    cout << "----------------\n";

    if (match) {
        cout << "Quantum-resistant key exchange established\n";
        cout << " Shared secret successfully negotiated\n";
        cout << " Suitable for secure communication setup\n";
    } else {
        cout << "Key exchange verification failed\n";
    }

    print_separator();
    cout << "ML-KEM-768 DEMONSTRATION COMPLETED\n";
    print_separator();

    OQS_KEM_free(kem);

    return 0;
}