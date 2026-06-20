"""
models.py
---------
Pydantic request and response models for all FastAPI endpoints.

Auth flow:
  - Register: username + password → returns user_id + both keypairs
  - Login:    username + password → returns user_id + both keypairs (re-derived from stored data)
              (Kyber SK is returned on register only; login re-returns what was cached client-side)

Sharing flow:
  - Upload:   sender searches recipient by username
  - Inbox:    GET /documents/inbox/{recipient_id} → list of waiting docs
  - Verify:   POST /document/verify  → checks Dilithium sig, returns uploader info
  - Decrypt:  POST /document/decrypt → Kyber decap + AES decrypt → file bytes
"""

from pydantic import BaseModel
from typing import Optional, List


# ── Auth ──────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterResponse(BaseModel):
    user_id: str
    username: str
    # Dilithium — for signing/identity
    dilithium_public_key: str
    dilithium_secret_key: str
    dilithium_algorithm: str
    # Kyber — for receiving encrypted documents
    kyber_public_key: str
    kyber_secret_key: str
    kyber_algorithm: str
    message: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    user_id: str
    username: str
    message: str


class UserSearchResponse(BaseModel):
    user_id: str
    username: str
    dilithium_public_key: str
    kyber_public_key: str
    dilithium_algorithm: str
    kyber_algorithm: str


class UserListResponse(BaseModel):
    users: List[UserSearchResponse]


# ── Document ──────────────────────────────────────────────────────────────────

class UploadResponse(BaseModel):
    document_id: str
    recipient_id: str
    recipient_username: str
    uploader_id: str
    uploader_username: str
    aes_key_encapsulated: str
    kyber_public_key_used: str
    nonce: str
    tag: str
    ciphertext_preview: str
    package_signature: str
    dilithium_public_key: str
    original_filename: str
    entropy_source: str
    message: str


class VerifySignatureRequest(BaseModel):
    document_id: str
    recipient_id: str


class VerifySignatureResponse(BaseModel):
    document_id: str
    signature_valid: bool
    uploader_id: str
    uploader_username: str
    uploader_dilithium_public_key: str
    filename: str
    uploaded_at: str
    message: str


class DecryptRequest(BaseModel):
    document_id: str
    recipient_id: str
    kyber_secret_key: str           # Recipient's own secret key — never stored on server


class DecryptResponse(BaseModel):
    document_id: str
    filename: str
    content_b64: str
    uploader_id: str
    uploader_username: str
    message: str


class InboxDocument(BaseModel):
    document_id: str
    filename: str
    uploader_id: str
    uploader_username: str
    uploaded_at: str
    entropy_source: str


class InboxResponse(BaseModel):
    recipient_id: str
    documents: List[InboxDocument]


class SentDocument(BaseModel):
    document_id: str
    filename: str
    recipient_id: str
    recipient_username: str
    uploaded_at: str


class SentResponse(BaseModel):
    uploader_id: str
    documents: List[SentDocument]


# ── Random ────────────────────────────────────────────────────────────────────

class SeedResponse(BaseModel):
    source: str
    backend: str
    seed_hex: str
    seed_bytes: int
    message: str


class RandomBytesResponse(BaseModel):
    requested_bytes: int
    hex: str
    decimal_sample: list
    source: str


# ── Status ────────────────────────────────────────────────────────────────────

class StatusResponse(BaseModel):
    entropy_source: str
    seed_initialized: bool
    kem_algorithm: str
    sig_algorithm: str
    aes_mode: str
    message: str