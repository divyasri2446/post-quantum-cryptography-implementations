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
        cout << hex << uppercase
             << setw(2) << setfill('0')
             << static_cast<int>(data[i]) << " ";
    }
    cout << dec << "\n";
}

int main() {

    print_separator();
    cout << "        ML-DSA-65 POST-QUANTUM DIGITAL SIGNATURE DEMO\n";
    print_separator();

    cout << "\nAlgorithm Information\n";
    cout << "---------------------\n";
    cout << "Algorithm      : ML-DSA-65\n";
    cout << "NIST Standard  : FIPS 204\n";
    cout << "Security Basis : Module Learning With Errors (MLWE)\n";
    cout << "Security Level : NIST Category 3\n";

    cout << "\n[1] Initializing ML-DSA-65...\n";

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == nullptr) {
        cerr << "ERROR: ML-DSA-65 not available.\n";
        return 1;
    }

    cout << "Status : SUCCESS\n";

    vector<uint8_t> public_key(sig->length_public_key);
    vector<uint8_t> secret_key(sig->length_secret_key);

    cout << "\n[2] Generating Key Pair...\n";

    if (OQS_SIG_keypair(
            sig,
            public_key.data(),
            secret_key.data()) != OQS_SUCCESS) {

        cerr << "Key generation failed.\n";
        return 1;
    }

    cout << "Public Key Size : "
         << sig->length_public_key
         << " bytes\n";

    cout << "Secret Key Size : "
         << sig->length_secret_key
         << " bytes\n";

    cout << "Status          : SUCCESS\n";

    string message = "Post Quantum Encryption";

    cout << "\n[3] Message Creation...\n";
    cout << "Message : " << message << "\n";

    vector<uint8_t> signature(sig->length_signature);
    size_t signature_len = 0;

    cout << "\n[4] Signing Message...\n";

    if (OQS_SIG_sign(
            sig,
            signature.data(),
            &signature_len,
            reinterpret_cast<const uint8_t*>(message.c_str()),
            message.length(),
            secret_key.data()) != OQS_SUCCESS) {

        cerr << "Signature generation failed.\n";
        return 1;
    }

    cout << "Signature Size : "
         << signature_len
         << " bytes\n";

    cout << "Status         : SUCCESS\n";

    cout << "\nSignature Preview:\n";
    print_hex_preview(signature);
   

    cout << "\n[5] Verifying Signature...\n";

    OQS_STATUS verify_status =
        OQS_SIG_verify(
            sig,
            reinterpret_cast<const uint8_t*>(message.c_str()),
            message.length(),
            signature.data(),
            signature_len,
            public_key.data());

    if (verify_status == OQS_SUCCESS) {
        cout << "Verification Status : VALID\n";
    } else {
        cout << "Verification Status : INVALID\n";
    }

    cout << "\nSecurity Outcome\n";
    cout << "----------------\n";

    if (verify_status == OQS_SUCCESS) {
        cout << "[OK] Message Integrity Verified\n";
        cout << "[OK] Signature Authenticity Verified\n";
        cout << "[OK] Quantum-Resistant Signature Valid\n";
    } else {
        cout << "[FAIL] Signature Verification Failed\n";
    }

    print_separator();
    cout << "ML-DSA-65 DEMONSTRATION COMPLETED\n";
    print_separator();

    OQS_SIG_free(sig);

    return 0;
}