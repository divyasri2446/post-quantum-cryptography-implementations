# Post-Quantum Cryptography Implementations using liboqs

## Overview

This repository presents the implementation and demonstration of NIST-standardized Post-Quantum Cryptography (PQC) algorithms using the Open Quantum Safe (liboqs) library in both C++ and Python.

The objective of this project is to understand, implement, and validate quantum-resistant cryptographic algorithms that can secure digital communication against future quantum computer attacks.

The project includes implementations of:

* ML-KEM-768 (FIPS 203) – Post-Quantum Key Exchange
* ML-DSA-65 (FIPS 204) – Post-Quantum Digital Signature
* SLH-DSA-SHA2-128f (FIPS 205) – Hash-Based Digital Signature

---

# Why Post-Quantum Cryptography?

Traditional public-key cryptographic algorithms such as RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECC) rely on mathematical problems that can be efficiently solved by large-scale quantum computers using Shor’s Algorithm.

This creates a significant security threat, often referred to as:

**"Harvest Now, Decrypt Later"**

In this scenario, encrypted data intercepted today can be stored and decrypted in the future when quantum computers become sufficiently powerful.

To address this challenge, NIST has standardized a new generation of cryptographic algorithms known as Post-Quantum Cryptography (PQC).

---

# Implemented Algorithms

## 1. ML-KEM-768 (FIPS 203)

### Purpose

ML-KEM (Module-Lattice Key Encapsulation Mechanism) is a quantum-resistant key exchange algorithm standardized by NIST.

### Security Foundation

* Module Learning With Errors (MLWE)
* Lattice-Based Cryptography

### Demonstrated Operations

* Key Pair Generation
* Encapsulation
* Ciphertext Generation
* Shared Secret Generation
* Decapsulation
* Shared Secret Verification

### Workflow

Alice:

1. Generates Public Key and Secret Key
2. Shares Public Key with Bob

Bob:

1. Uses Alice's Public Key
2. Generates Ciphertext
3. Generates Shared Secret

Alice:

1. Uses Ciphertext and Secret Key
2. Recovers Shared Secret

Verification:

1. Bob's Shared Secret
2. Alice's Shared Secret
3. Equality Check

Successful verification confirms a secure quantum-resistant key exchange.

---

## 2. ML-DSA-65 (FIPS 204)

### Purpose

ML-DSA is a post-quantum digital signature algorithm standardized by NIST.

### Security Foundation

* Module Learning With Errors (MLWE)
* Lattice-Based Cryptography

### Demonstrated Operations

* Key Pair Generation
* Message Signing
* Signature Verification

### Workflow

Signer:

1. Generates Public Key and Secret Key
2. Creates Message
3. Signs Message using Secret Key

Verifier:

1. Receives Message
2. Receives Signature
3. Uses Public Key
4. Verifies Signature

Successful verification confirms:

* Integrity
* Authenticity
* Non-Repudiation

---

## 3. SLH-DSA-SHA2-128f (FIPS 205)

### Purpose

SLH-DSA is a hash-based post-quantum digital signature algorithm standardized by NIST.

### Security Foundation

* Cryptographic Hash Functions
* Stateless Hash-Based Signatures

### Demonstrated Operations

* Key Pair Generation
* Message Signing
* Signature Verification
* Tampering Detection

### Workflow

Signer:

1. Generates Key Pair
2. Signs Original Message

Verifier:

1. Verifies Original Message
2. Validates Signature

Tampering Test:

1. Message Modified
2. Verification Attempted Again
3. Verification Fails

This demonstrates message integrity protection and tamper detection.

---

# Project Structure

```text
PostQuantumCryptography/
│
├── cpp/
│   ├── mlkem_demo.cpp
│   ├── mldsa_demo.cpp
│   └── slhdsa_demo.cpp
│
├── python/
│   ├── mlkem_demo.py
│   ├── mldsa_demo.py
│   └── slhdsa_demo.py
│
├── screenshots/
│   ├── ml_kem.png
│   ├── ml_dsa.png
│   └── slh_dsa.png
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

# Technologies Used

* C++
* Python
* liboqs (Open Quantum Safe)
* Open Quantum Safe Framework
* NIST PQC Standards
* MSYS2 / MinGW
* Git & GitHub

---

# Results

### ML-KEM-768

* Successful Key Pair Generation
* Successful Encapsulation
* Successful Decapsulation
* Shared Secret Match Verified

### ML-DSA-65

* Successful Key Pair Generation
* Successful Signature Creation
* Successful Signature Verification

### SLH-DSA-SHA2-128f

* Successful Key Pair Generation
* Successful Signature Creation
* Successful Signature Verification
* Successful Tampering Detection 
