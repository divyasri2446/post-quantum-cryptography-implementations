"""
main.py
-------
Quantum-Safe Secure Document Portal — FastAPI backend.

AUTH MODEL:
  Register: username + password. Server hashes password (bcrypt).
            Returns user_id + both Dilithium + Kyber keypairs.
            Kyber SECRET KEY returned once, never stored server-side.
  Login:    username + password → validates, returns user_id.
            Client holds keys in localStorage from the original register call.

SHARING MODEL:
  Sender searches for recipient by username → /users/search?q=alice
  Uploads file → encrypted to recipient's Kyber public key.
  Recipient hits GET /documents/inbox/{recipient_id} to see waiting docs.

DECRYPT FLOW (two steps):
  Step 1 — Verify:  POST /document/verify    → checks Dilithium sig, returns uploader info.
                    No key needed. Safe to show before committing to decrypt.
  Step 2 — Decrypt: POST /document/decrypt   → Kyber decap + AES decrypt → file bytes.

QUANTUM SEEDING:
  AES key/nonce, Kyber keypair, Dilithium keypair, user_id, doc_id → all quantum-seeded.
"""

import base64
import datetime
import hashlib
import hmac as hmac_module

from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()

from quantum_rng import initialize_quantum_seed, get_random_bytes, get_entropy_source
from pqc import (
    kyber_keygen, kyber_encapsulate, kyber_decapsulate,
    dilithium_keygen, dilithium_sign, dilithium_verify,
    KEM_ALG, SIG_ALG,
)
from aes_crypto import aes_encrypt, aes_decrypt
from models import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    UserSearchResponse, UserListResponse,
    UploadResponse,
    VerifySignatureRequest, VerifySignatureResponse,
    DecryptRequest, DecryptResponse,
    InboxDocument, InboxResponse,
    SentDocument, SentResponse,
    SeedResponse, RandomBytesResponse, StatusResponse,
)
from storage import users, user_id_to_username, documents


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_id(n_bytes: int = 6) -> str:
    """Generate a short hex ID from quantum DRBG."""
    return get_random_bytes(n_bytes).hex()


def hash_password(password: str) -> str:
    """Simple PBKDF2 password hash (bcrypt not in stdlib; use pbkdf2 instead)."""
    salt = b"quantumvault_salt_v1"   # in prod: per-user random salt stored alongside hash
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()


def check_password(password: str, stored_hash: str) -> bool:
    return hmac_module.compare_digest(hash_password(password), stored_hash)


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Quantum-Safe Secure Document Portal",
    description="AES-256-GCM + ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium), seeded by real quantum randomness.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    print("[startup] Initializing quantum seed...")
    info = initialize_quantum_seed(force_simulator=False)
    print(f"[startup] Entropy source: {info['source']} | Backend: {info['backend']}")


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


# ── Status ────────────────────────────────────────────────────────────────────

@app.get("/status", response_model=StatusResponse)
async def get_status():
    source = get_entropy_source()
    initialized = source != "not_initialized"
    return StatusResponse(
        entropy_source=source,
        seed_initialized=initialized,
        kem_algorithm=KEM_ALG,
        sig_algorithm=SIG_ALG,
        aes_mode="AES-256-GCM",
        message="System operational" if initialized else "Quantum seed not yet initialized",
    )


# ── Quantum Randomness ────────────────────────────────────────────────────────

@app.get("/random/seed", response_model=SeedResponse)
async def refresh_quantum_seed(simulator: bool = False):
    info = initialize_quantum_seed(force_simulator=simulator)
    return SeedResponse(
        source=info["source"],
        backend=info["backend"],
        seed_hex=info["seed_hex"],
        seed_bytes=info["seed_bytes"],
        message=f"Quantum seed generated via {info['backend']}",
    )


@app.get("/random/bytes", response_model=RandomBytesResponse)
async def get_random_bytes_endpoint(n: int = 32):
    if n < 1 or n > 1024:
        raise HTTPException(status_code=400, detail="n must be between 1 and 1024")
    rand = get_random_bytes(n)
    return RandomBytesResponse(
        requested_bytes=n,
        hex=rand.hex(),
        decimal_sample=list(rand[:10]),
        source=get_entropy_source(),
    )


# ── Auth: Register ────────────────────────────────────────────────────────────

@app.post("/auth/register", response_model=RegisterResponse)
async def register(req: RegisterRequest):
    """
    Register a new user with username + password.
    Generates Dilithium + Kyber keypairs (quantum-seeded).
    Kyber secret key returned ONCE, never stored server-side.
    """
    username = req.username.strip().lower()
    if not username or len(username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters.")
    if not req.password or len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if username in users:
        raise HTTPException(status_code=409, detail=f"Username '{username}' is already taken.")

    user_id = make_id(4)          # 8-char hex, quantum-sourced
    dil_keys = dilithium_keygen()
    kyb_keys = kyber_keygen()

    users[username] = {
        "user_id": user_id,
        "username": username,
        "password_hash": hash_password(req.password),
        "dilithium_public_key": dil_keys["public_key"],
        "dilithium_algorithm": dil_keys["algorithm"],
        "kyber_public_key": kyb_keys["public_key"],
        "kyber_algorithm": kyb_keys["algorithm"],
        "registered_at": datetime.datetime.utcnow().isoformat(),
    }
    user_id_to_username[user_id] = username

    return RegisterResponse(
        user_id=user_id,
        username=username,
        dilithium_public_key=dil_keys["public_key"],
        dilithium_secret_key=dil_keys["secret_key"],
        dilithium_algorithm=dil_keys["algorithm"],
        kyber_public_key=kyb_keys["public_key"],
        kyber_secret_key=kyb_keys["secret_key"],   # returned once, never stored
        kyber_algorithm=kyb_keys["algorithm"],
        message=(
            f"Welcome, {username}! Save your Kyber secret key — "
            "the server does NOT store it. You need it to decrypt documents."
        ),
    )


# ── Auth: Login ───────────────────────────────────────────────────────────────

@app.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """Login with username + password. Returns user_id for subsequent calls."""
    username = req.username.strip().lower()
    if username not in users:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not check_password(req.password, users[username]["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    return LoginResponse(
        user_id=users[username]["user_id"],
        username=username,
        message=f"Welcome back, {username}!",
    )


# ── Users: Search ─────────────────────────────────────────────────────────────

@app.get("/users/search", response_model=UserListResponse)
async def search_users(q: str = Query("", min_length=0)):
    """Search registered users by username prefix (case-insensitive)."""
    q = q.strip().lower()
    result = []
    for uname, info in users.items():
        if q == "" or uname.startswith(q) or q in uname:
            result.append(UserSearchResponse(
                user_id=info["user_id"],
                username=uname,
                dilithium_public_key=info["dilithium_public_key"],
                kyber_public_key=info["kyber_public_key"],
                dilithium_algorithm=info["dilithium_algorithm"],
                kyber_algorithm=info["kyber_algorithm"],
            ))
    return UserListResponse(users=result)


# ── Sign helper (for upload identity proof) ───────────────────────────────────

class SignRequest(BaseModel):
    secret_key: str
    message: str

@app.post("/pqc/sign")
async def pqc_sign(req: SignRequest):
    result = dilithium_sign(
        secret_key_hex=req.secret_key,
        message=req.message.encode(),
    )
    return {"signature": result["signature"]}


# ── Document: Upload ──────────────────────────────────────────────────────────

@app.post("/document/upload", response_model=UploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    uploader_id: str = Form(...),
    uploader_secret_key: str = Form(None),       # required for "signed" mode only
    uploader_signature: str = Form(None),        # required for "signed" mode only
    recipient_ids: str = Form(...),               # comma-separated list of recipient user_ids
    mode: str = Form("signed"),                  # "encrypted" = AES+Kyber only | "signed" = AES+Kyber+Dilithium
):
    """
    Upload pipeline — supports TWO modes:
      - "signed"    (mode="signed"):    full AES-256-GCM + Kyber encapsulation + Dilithium signature
      - "encrypted" (mode="encrypted"): AES-256-GCM + Kyber encapsulation, NO Dilithium signature

    Plain/unencrypted send is intentionally removed — all documents are at minimum encrypted.

    For sends to MULTIPLE recipients (Kyber is single-recipient-per-encapsulation):
      1. Encrypt the file ONCE with a fresh AES key (ciphertext identical for everyone)
      2. For EACH recipient: Kyber-encapsulate that SAME AES key to their public key
         (different ciphertext per recipient, since each has a different public key)
      3. If mode="signed": sign EACH recipient's package separately (signed bytes differ per recipient,
         since the wrapped key differs)
      4. Store one document row per recipient, all sharing the same group_id
    """
    if mode not in ("encrypted", "signed"):
        raise HTTPException(status_code=400, detail="mode must be 'encrypted' or 'signed'.")
    secure = True  # both modes are encrypted; 'signed' adds Dilithium on top
    recipient_id_list = [r.strip() for r in recipient_ids.split(",") if r.strip()]
    if not recipient_id_list:
        raise HTTPException(status_code=400, detail="No recipients specified.")

    uploader_username = user_id_to_username.get(uploader_id)
    if not uploader_username or uploader_username not in users:
        raise HTTPException(status_code=404, detail="Uploader not found. Register first.")
    uploader_info = users[uploader_username]

    if mode == "signed":
        if not uploader_secret_key:
            raise HTTPException(status_code=400, detail="Dilithium secret key required for 'signed' mode.")
        identity_check = dilithium_verify(
            public_key_hex=uploader_info["dilithium_public_key"],
            message=file.filename.encode(),
            signature_hex=uploader_signature or "",
        )
        if not identity_check["valid"]:
            raise HTTPException(status_code=403, detail="Identity verification failed. Upload rejected.")

    file_bytes = await file.read()
    group_id = make_id(6)
    created_doc_ids = []
    last_recipient_username = None

    if secure:
        enc = aes_encrypt(file_bytes)
        aes_key_bytes = bytes.fromhex(enc["aes_key"])

        for recipient_id in recipient_id_list:
            recipient_username = user_id_to_username.get(recipient_id)
            if not recipient_username or recipient_username not in users:
                continue
            recipient_info = users[recipient_username]

            encap = kyber_encapsulate(recipient_info["kyber_public_key"])
            kyber_shared = bytes.fromhex(encap["shared_secret"])
            wrapped_aes_key = bytes(a ^ b for a, b in zip(aes_key_bytes, kyber_shared[:32]))

            if mode == "signed":
                package_bytes = (
                    bytes.fromhex(enc["ciphertext"]) +
                    bytes.fromhex(enc["tag"]) +
                    bytes.fromhex(encap["ciphertext"]) +
                    wrapped_aes_key
                )
                package_sig = dilithium_sign(secret_key_hex=uploader_secret_key, message=package_bytes)
            else:
                package_sig = {"signature": ""}   # encrypted mode — no signature

            doc_id = hashlib.sha256(
                bytes.fromhex(enc["ciphertext"]) +
                bytes.fromhex(enc["tag"]) +
                bytes.fromhex(enc["nonce"]) +
                bytes.fromhex(encap["ciphertext"]) +
                recipient_id.encode()
            ).hexdigest()

            documents[doc_id] = {
                "group_id": group_id,
                "is_secure": mode,   # "signed" | "encrypted"
                "ciphertext": enc["ciphertext"],
                "nonce": enc["nonce"],
                "tag": enc["tag"],
                "kyber_ciphertext": encap["ciphertext"],
                "wrapped_aes_key": wrapped_aes_key.hex(),
                "package_signature": package_sig["signature"],
                "dilithium_public_key": uploader_info["dilithium_public_key"],
                "recipient_id": recipient_id,
                "recipient_username": recipient_username,
                "uploader_id": uploader_id,
                "uploader_username": uploader_username,
                "filename": file.filename,
                "uploaded_at": datetime.datetime.utcnow().isoformat(),
                "entropy_source": get_entropy_source(),
            }
            created_doc_ids.append(doc_id)
            last_recipient_username = recipient_username



    if not created_doc_ids:
        raise HTTPException(status_code=404, detail="No valid recipients found.")

    return UploadResponse(
        document_id=created_doc_ids[0],
        recipient_id=recipient_id_list[0],
        recipient_username=last_recipient_username or "",
        uploader_id=uploader_id,
        uploader_username=uploader_username,
        aes_key_encapsulated=documents[created_doc_ids[0]].get("kyber_ciphertext", ""),
        kyber_public_key_used="",
        nonce=documents[created_doc_ids[0]].get("nonce", ""),
        tag=documents[created_doc_ids[0]].get("tag", ""),
        ciphertext_preview=documents[created_doc_ids[0]]["ciphertext"][:40],
        package_signature=documents[created_doc_ids[0]].get("package_signature", ""),
        dilithium_public_key=uploader_info["dilithium_public_key"],
        original_filename=file.filename,
        entropy_source=documents[created_doc_ids[0]]["entropy_source"],
        message=(
            f"Document '{file.filename}' sent to {len(created_doc_ids)} recipient(s) "
            f"(mode: {'encrypted + signed' if mode == 'signed' else 'encrypted only'}). "
            f"Group ID: {group_id}."
        ),
    )


# ── Document: Inbox ───────────────────────────────────────────────────────────

@app.get("/documents/inbox/{recipient_id}", response_model=InboxResponse)
async def get_inbox(recipient_id: str):
    """Return all documents waiting for this recipient."""
    result = []
    for doc_id, doc in documents.items():
        if doc["recipient_id"] == recipient_id:
            result.append(InboxDocument(
                document_id=doc_id,
                filename=doc["filename"],
                uploader_id=doc["uploader_id"],
                uploader_username=doc.get("uploader_username", doc["uploader_id"]),
                uploaded_at=doc.get("uploaded_at", ""),
                entropy_source=doc.get("entropy_source", ""),
                is_secure=doc.get("is_secure", "true"),
            ))
    return InboxResponse(recipient_id=recipient_id, documents=result)


# ── Document: Sent ────────────────────────────────────────────────────────────

@app.get("/documents/sent/{uploader_id}", response_model=SentResponse)
async def get_sent(uploader_id: str):
    """Return all documents sent by this user."""
    result = []
    for doc_id, doc in documents.items():
        if doc["uploader_id"] == uploader_id:
            result.append(SentDocument(
                document_id=doc_id,
                filename=doc["filename"],
                recipient_id=doc["recipient_id"],
                recipient_username=doc.get("recipient_username", doc["recipient_id"]),
                uploaded_at=doc.get("uploaded_at", ""),
                is_secure=doc.get("is_secure", "true"),
            ))
    return SentResponse(uploader_id=uploader_id, documents=result)


# ── Document: Verify Signature (Step 1 of receive) ───────────────────────────

@app.post("/document/verify", response_model=VerifySignatureResponse)
async def verify_document_signature(req: VerifySignatureRequest):
    """
    Step 1 of receiving a document.
    Verifies the Dilithium signature on the encrypted package.
    Returns uploader info (including their Dilithium public key) for display.
    No Kyber secret key needed here — this is purely identity verification.
    """
    if req.document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found.")

    doc = documents[req.document_id]

    if req.recipient_id != doc["recipient_id"]:
        raise HTTPException(status_code=403, detail="You are not the intended recipient.")

    if doc.get("is_secure") == "encrypted":
        return VerifySignatureResponse(
            document_id=req.document_id,
            signature_valid=False,
            uploader_id=doc["uploader_id"],
            uploader_username=doc.get("uploader_username", doc["uploader_id"]),
            uploader_dilithium_public_key=doc["dilithium_public_key"],
            filename=doc["filename"],
            uploaded_at=doc.get("uploaded_at", ""),
            message=(
                "ℹ This document was sent in 'encrypted' mode — "
                "it is Kyber+AES encrypted but carries no Dilithium signature. "
                "Authenticity cannot be verified; proceed to decrypt only if you trust the sender."
            ),
        )

    package_bytes = (
        bytes.fromhex(doc["ciphertext"]) +
        bytes.fromhex(doc["tag"]) +
        bytes.fromhex(doc["kyber_ciphertext"]) +
        bytes.fromhex(doc["wrapped_aes_key"])
    )
    verify = dilithium_verify(
        public_key_hex=doc["dilithium_public_key"],
        message=package_bytes,
        signature_hex=doc["package_signature"],
    )

    return VerifySignatureResponse(
        document_id=req.document_id,
        signature_valid=verify["valid"],
        uploader_id=doc["uploader_id"],
        uploader_username=doc.get("uploader_username", doc["uploader_id"]),
        uploader_dilithium_public_key=doc["dilithium_public_key"],
        filename=doc["filename"],
        uploaded_at=doc.get("uploaded_at", ""),
        message=(
            "✓ Dilithium signature verified — document is authentic and untampered."
            if verify["valid"]
            else "✗ Signature invalid — document may be tampered or forged."
        ),
    )


# ── Document: Decrypt (Step 2 of receive) ────────────────────────────────────

@app.post("/document/decrypt", response_model=DecryptResponse)
async def decrypt_document(req: DecryptRequest):
    """
    Step 2 of receiving a document (after verify).
    Kyber decapsulate → recover AES key → AES-256-GCM decrypt → return file.

    NOTE: if the document was sent via "Send" (insecure demo mode), it was
    never encrypted in the first place — short-circuit and return it as-is.
    """
    if req.document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found.")

    doc = documents[req.document_id]

    if req.recipient_id != doc["recipient_id"]:
        raise HTTPException(status_code=403, detail="You are not the intended recipient.")

    # Kyber decapsulate with recipient's secret key
    try:
        decap = kyber_decapsulate(
            secret_key_hex=req.kyber_secret_key,
            ciphertext_hex=doc["kyber_ciphertext"],
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Kyber decapsulation failed — wrong secret key or corrupted data.",
        )

    kyber_shared = bytes.fromhex(decap["shared_secret"])
    wrapped = bytes.fromhex(doc["wrapped_aes_key"])
    aes_key_bytes = bytes(a ^ b for a, b in zip(wrapped, kyber_shared[:32]))

    try:
        plaintext = aes_decrypt(
            aes_key_hex=aes_key_bytes.hex(),
            nonce_hex=doc["nonce"],
            ciphertext_hex=doc["ciphertext"],
            tag_hex=doc["tag"],
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="AES-GCM tag verification failed — wrong key or corrupted data.",
        )

    return DecryptResponse(
        document_id=req.document_id,
        filename=doc["filename"],
        content_b64=base64.b64encode(plaintext).decode(),
        uploader_id=doc["uploader_id"],
        uploader_username=doc.get("uploader_username", doc["uploader_id"]),
        message=f"'{doc['filename']}' decrypted successfully.",
    )