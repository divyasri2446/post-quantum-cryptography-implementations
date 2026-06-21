# Post-Quantum Cryptography Implementations

> NIST-standardized post-quantum algorithms implemented in Python and C++, plus **QuantumVault** — a fully functional quantum-safe encrypted document sharing portal.

---

## What's Inside

This repo has two parts:

**1. Algorithm Implementations** — standalone Python and C++ implementations of all three NIST PQC standards using liboqs.

**2. QuantumVault** — a full-stack web app that puts those algorithms to real use: end-to-end encrypted document sharing with quantum-seeded randomness, Kyber key encapsulation, Dilithium signatures, and AES-256-GCM encryption.

---

## Algorithms Implemented

| Algorithm | Standard | Type | Purpose |
|-----------|----------|------|---------|
| ML-KEM-768 (Kyber) | FIPS 203 | Key Encapsulation | Encrypting the AES key to recipient |
| ML-DSA-65 (Dilithium) | FIPS 204 | Digital Signatures | Signing documents and verifying identity |
| SLH-DSA-SHA2-128f | FIPS 205 | Hash-Based Signatures | Stateless hash-based signing |

All three are quantum-resistant — secure against both classical and quantum computers.

---

## QuantumVault — Quantum-Safe Document Portal

### Live Demo
🔗 **[quantumvault-production.up.railway.app](https://quantumvault-production.up.railway.app)**

### What it does

QuantumVault lets users send encrypted files to each other such that:
- Only the intended recipient can decrypt the file
- The server **never sees** the AES key or either secret key in plaintext
- Every key, nonce, salt, and document ID is seeded from **real quantum randomness** (IBM Quantum hardware or Qiskit AerSimulator fallback)
- Every encrypted package is **digitally signed** — tampering is detected before decryption
- Documents are stored using **content-addressed IDs** (SHA-256 of the encrypted content — no arbitrary IDs)

### Crypto Stack

```
Randomness:   IBM Quantum (Hadamard circuit, 5 qubits, 512 shots) → SHA-256 → HMAC-DRBG expansion
              Fallback: Qiskit AerSimulator (24 qubits × 11 runs)
Encryption:   AES-256-GCM  (file content — key + nonce from HMAC-DRBG)
Key Wrapping: ML-KEM-768   (Kyber) — encapsulate AES key to recipient's public key
              XOR-wrap: wrapped_aes_key = aes_key ⊕ kyber_shared_secret
Signatures:   ML-DSA-65    (Dilithium) — signs filename for identity + signs encrypted package
Storage:      SQLite via SQLAlchemy ORM (secret keys never stored server-side)
```

### Quantum Seeding Details

The QRNG pipeline runs at server startup:

1. **IBM Quantum hardware** — runs a Hadamard + measure circuit (5 qubits, 512 shots) via `SamplerV2` primitive, using channel `ibm_quantum_platform`. Measurement outcomes are concatenated and SHA-256 hashed to produce a 32-byte seed.
2. **AerSimulator fallback** — if IBM hardware is unavailable, runs 11 circuits of 24 qubits each (264 bits total) locally via Qiskit Aer.
3. **HMAC-DRBG expansion** — the quantum seed is used as the HMAC key; a counter is incremented per block to produce unlimited random bytes. All AES keys, nonces, salts, tokens, and document IDs are derived from this stream.

**Quantum seeding of PQC keypairs:**
- **Kyber** — uses `kem.generate_keypair_seed(quantum_bytes)` directly. Deterministic and fully quantum-seeded.
- **Dilithium** — seeds liboqs's internal NIST KAT RNG via `oqs.randombytes_nist_kat_init_256bit(48_quantum_bytes)` before calling `generate_keypair()`. Falls back silently if the API is unavailable in the installed liboqs build.

### Send Modes

The upload endpoint supports two modes, selectable from the UI:

| Mode | Button | What it does |
|------|--------|--------------|
| `encrypted` | **Send** | AES-256-GCM + Kyber encapsulation only. No Dilithium signature — faster, anonymous sender. |
| `signed` | **Send Securely** | AES-256-GCM + Kyber encapsulation + Dilithium signature. Full authentication + tamper detection. |

Both modes require the recipient's Kyber public key and always encrypt the file — plain/unencrypted send is intentionally not supported.

**Multi-recipient support:** the file is encrypted once (same AES ciphertext for all), but the AES key is Kyber-encapsulated separately per recipient (each gets their own `kyber_ciphertext` and `wrapped_aes_key`). All copies share a `group_id`.

### Encryption Flow

**Mode: `signed` (Send Securely)**
```
SENDER
  │
  ├─ 1. Dilithium verify identity    (sign filename → server checks against stored public key)
  ├─ 2. AES-256-GCM encrypt file     (key + nonce from quantum HMAC-DRBG)
  ├─ 3. Kyber encapsulate            (→ kyber_ciphertext + shared_secret, per recipient)
  ├─ 4. XOR wrap AES key             (wrapped_aes_key = aes_key ⊕ shared_secret[:32])
  ├─ 5. Dilithium sign package       (signs ciphertext + tag + kyber_ciphertext + wrapped_aes_key)
  └─ 6. Store in SQLite              (doc_id = SHA-256 of encrypted content — no raw keys stored)

RECIPIENT
  │
  ├─ 1. Dilithium verify signature   (confirm authenticity + detect tampering)
  ├─ 2. Kyber decapsulate            (→ recover shared_secret using own secret key)
  ├─ 3. XOR unwrap AES key           (aes_key = wrapped_aes_key ⊕ shared_secret[:32])
  └─ 4. AES-256-GCM decrypt          (GCM tag also verifies integrity)
```

**Mode: `encrypted` (Send)**
```
SENDER
  │
  ├─ 1. AES-256-GCM encrypt file     (key + nonce from quantum HMAC-DRBG)
  ├─ 2. Kyber encapsulate            (→ kyber_ciphertext + shared_secret, per recipient)
  ├─ 3. XOR wrap AES key             (wrapped_aes_key = aes_key ⊕ shared_secret[:32])
  └─ 4. Store in SQLite              (package_signature stored as empty string)

RECIPIENT
  │
  ├─ 1. Kyber decapsulate            (→ recover shared_secret)
  ├─ 2. XOR unwrap AES key           (aes_key = wrapped_aes_key ⊕ shared_secret[:32])
  └─ 3. AES-256-GCM decrypt          (GCM tag verifies integrity)
```

### Key Security Design

- **Kyber secret key** — returned to user once at registration, never stored on server. Saved in browser localStorage.
- **Dilithium secret key** — same. Never stored server-side.
- **AES key** — generated fresh per file from quantum HMAC-DRBG, XOR-wrapped with Kyber shared secret, then discarded. Only `wrapped_aes_key` is stored.
- **Document ID** — `SHA-256(ciphertext + tag + nonce + kyber_ciphertext + recipient_id)` — content-addressed, full 64-character hash, no truncation.
- **Group ID** — links multiple per-recipient copies of the same upload together.
- **Quantum seeding** — the app tries IBM Quantum hardware (`ibm_quantum_platform` channel, CRN instance) on startup. Falls back to AerSimulator automatically. All randomness flows from this single quantum seed via HMAC-DRBG.

### IBM Quantum Setup

To use real quantum hardware:

1. Register at [quantum.cloud.ibm.com](https://quantum.cloud.ibm.com)
2. Navigate to your profile → **My IBM Cloud API Keys** → Create a key (e.g. named `qrng`)
3. On the dashboard, find your `open-instance` → copy the **CRN** (format: `crn:v1:bluemix:public:quantum-computing:us-east:a/...`)
4. Set in `.env`:

```env
IBM_QUANTUM_TOKEN=your_api_key_here
IBM_QUANTUM_INSTANCE=crn:v1:bluemix:public:quantum-computing:us-east:a/...
DATABASE_PATH=quantumvault.db
```

The app uses channel `ibm_quantum_platform`, auto-selects the least busy backend (ibm_marrakesh, ibm_fez, or ibm_kingston — all 156 qubits), and uses the `SamplerV2` primitive. Each QRNG run consumes ~2 seconds of QPU time. Without a token, the app falls back to AerSimulator automatically.

### Screenshots

#### Sender — Signing and Encrypting
![Sender](screenshots/sender.png)

#### Quantum RNG — System Status
![System](screenshots/System.png)

#### Receiver — Signature Verification
![Verification](screenshots/image-2.png)

#### Receiver — Decryption
![Decryption](screenshots/image-3.png)

---

## Project Structure

```
post-quantum-cryptography-implementations/
│
├── cpp/                        # C++ implementations
│   ├── kyber/                  # ML-KEM-768
│   ├── dilithium/              # ML-DSA-65
│   └── slh_dsa/                # SLH-DSA-SHA2-128f
│
├── python/                     # Python implementations
│   ├── kyber.py                # ML-KEM-768
│   ├── dilithium.py            # ML-DSA-65
│   └── slh_dsa.py              # SLH-DSA-SHA2-128f
│
├── pqcimp/                     # QuantumVault web app
│   ├── main.py                 # FastAPI backend — all endpoints
│   ├── pqc.py                  # Kyber + Dilithium via liboqs
│   ├── aes_crypto.py           # AES-256-GCM encrypt/decrypt
│   ├── quantum_rng.py          # IBM Quantum QRNG + HMAC-DRBG expansion
│   ├── storage.py              # SQLite via SQLAlchemy ORM
│   ├── models.py               # Pydantic request/response models
│   ├── static/
│   │   └── index.html          # Full frontend (single HTML file)
│   ├── Dockerfile              # Docker container build
│   └── .env.example            # Environment variable template
│
├── screenshots/
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- Docker (optional, for containerized run)
- IBM Quantum account (optional, for real hardware randomness)

### Install Dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` includes:
```
fastapi
uvicorn
qiskit
qiskit-ibm-runtime
qiskit-aer
liboqs-python
pycryptodome
python-dotenv
pydantic
python-multipart
sqlalchemy
```

> **Windows note:** `liboqs-python` compiles a C library during install. If you hit permission errors, run as Administrator or download a prebuilt `.whl` from the [liboqs-python releases page](https://github.com/open-quantum-safe/liboqs-python/releases). You may also need to set `OQS_INSTALL_PATH` to point to a prebuilt `liboqs.dll`.

### Environment Variables

Create a `.env` file in `pqcimp/`:

```env
IBM_QUANTUM_TOKEN=your_api_key_here
IBM_QUANTUM_INSTANCE=crn:v1:bluemix:public:quantum-computing:us-east:a/...
DATABASE_PATH=quantumvault.db
```

Without `IBM_QUANTUM_TOKEN`, the app automatically falls back to Qiskit AerSimulator for quantum randomness — no setup needed.

### Run Locally

```bash
cd pqcimp
uvicorn main:app --reload --port 8000
```

Visit `http://localhost:8000`

### Run with Docker

```bash
cd pqcimp
docker build -t quantumvault .
docker run -p 8000:8000 \
  -e IBM_QUANTUM_TOKEN=your_token \
  -e IBM_QUANTUM_INSTANCE=your_crn \
  quantumvault
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves frontend |
| GET | `/status` | Entropy source + algorithm info |
| GET | `/random/seed` | Trigger fresh quantum seed generation |
| GET | `/random/bytes?n=32` | Generate n quantum-seeded random bytes |
| POST | `/auth/register` | Create account — returns Dilithium + Kyber keypairs |
| POST | `/auth/login` | Verify password — returns user_id |
| GET | `/users/search?q=alice` | Search users by username |
| POST | `/pqc/sign` | Sign a message with Dilithium secret key |
| POST | `/document/upload` | Full pipeline: verify → encrypt → encapsulate → sign |
| GET | `/documents/inbox/{user_id}` | List documents received by user |
| GET | `/documents/sent/{user_id}` | List documents sent by user |
| POST | `/document/verify` | Verify Dilithium signature on a stored package |
| POST | `/document/decrypt` | Decapsulate Kyber + AES decrypt → return file |

Full interactive docs available at `/docs` (Swagger UI).

---

## Technologies Used

- **Python** + **C++**
- **FastAPI** + **Uvicorn**
- **liboqs** (Open Quantum Safe — NIST PQC reference implementations)
- **Qiskit** + **IBM Quantum** (SamplerV2 primitive, `ibm_quantum_platform` channel)
- **AES-256-GCM** (pycryptodome)
- **SQLite** + **SQLAlchemy ORM**
- **Docker**
- **Railway** (deployment)

---

## References

- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe — liboqs](https://openquantumsafe.org/)
- [IBM Quantum Platform](https://quantum.cloud.ibm.com/)
- [Qiskit IBM Runtime — SamplerV2](https://docs.quantum.ibm.com/api/qiskit-ibm-runtime/sampler-v2)

---
