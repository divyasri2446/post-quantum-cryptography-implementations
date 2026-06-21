"""
storage.py
----------
SQLite-backed storage (via SQLAlchemy) for users and encrypted documents.
Replaces the old in-memory dicts so data survives restarts/redeploys.

DB file path comes from DATABASE_PATH env var, defaulting to a local file.
On Railway, point this at a path inside an attached persistent volume,
e.g. DATABASE_PATH=/data/quantumvault.db
"""

import os
import datetime
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("DATABASE_PATH", "quantumvault.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# ── Models ──────────────────────────────────────────────────────────────────

class UserModel(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)   # keyed by username, same as before
    user_id = Column(String, unique=True, index=True)
    password_hash = Column(String)
    dilithium_public_key = Column(String)
    dilithium_algorithm = Column(String)
    kyber_public_key = Column(String)
    kyber_algorithm = Column(String)
    registered_at = Column(String)


class DocumentModel(Base):
    __tablename__ = "documents"

    document_id = Column(String, primary_key=True)
    group_id = Column(String, index=True)        # links multiple recipient copies of the same upload
    is_secure = Column(String, default="true")   # "true" = encrypted+signed, "false" = plain demo send
    ciphertext = Column(String)
    nonce = Column(String)
    tag = Column(String)
    kyber_ciphertext = Column(String)
    wrapped_aes_key = Column(String)
    package_signature = Column(String)
    dilithium_public_key = Column(String)
    recipient_id = Column(String, index=True)
    recipient_username = Column(String)
    uploader_id = Column(String, index=True)
    uploader_username = Column(String)
    filename = Column(String)
    uploaded_at = Column(String)
    entropy_source = Column(String)


Base.metadata.create_all(engine)


# ── Dict-like wrapper classes ────────────────────────────────────────────────
# These mimic the old dict interface (users[username] = {...}, "x" in users, etc.)
# so main.py needs MINIMAL changes.

def _user_to_dict(u: UserModel) -> dict:
    return {
        "user_id": u.user_id,
        "username": u.username,
        "password_hash": u.password_hash,
        "dilithium_public_key": u.dilithium_public_key,
        "dilithium_algorithm": u.dilithium_algorithm,
        "kyber_public_key": u.kyber_public_key,
        "kyber_algorithm": u.kyber_algorithm,
        "registered_at": u.registered_at,
    }


def _doc_to_dict(d: DocumentModel) -> dict:
    return {
        "group_id": d.group_id,
        "is_secure": d.is_secure,
        "ciphertext": d.ciphertext,
        "nonce": d.nonce,
        "tag": d.tag,
        "kyber_ciphertext": d.kyber_ciphertext,
        "wrapped_aes_key": d.wrapped_aes_key,
        "package_signature": d.package_signature,
        "dilithium_public_key": d.dilithium_public_key,
        "recipient_id": d.recipient_id,
        "recipient_username": d.recipient_username,
        "uploader_id": d.uploader_id,
        "uploader_username": d.uploader_username,
        "filename": d.filename,
        "uploaded_at": d.uploaded_at,
        "entropy_source": d.entropy_source,
    }


class _UsersTable:
    """Drop-in replacement for the old `users` dict, backed by SQLite."""

    def __setitem__(self, username, value: dict):
        value = {k: v for k, v in value.items() if k != "username"}
        session = SessionLocal()
        try:
            existing = session.get(UserModel, username)
            if existing:
                for k, v in value.items():
                    setattr(existing, k, v)
            else:
                session.add(UserModel(username=username, **value))
            session.commit()
        finally:
            session.close()

    def __getitem__(self, username):
        session = SessionLocal()
        try:
            u = session.get(UserModel, username)
            if u is None:
                raise KeyError(username)
            return _user_to_dict(u)
        finally:
            session.close()

    def __contains__(self, username):
        session = SessionLocal()
        try:
            return session.get(UserModel, username) is not None
        finally:
            session.close()

    def items(self):
        session = SessionLocal()
        try:
            return [(u.username, _user_to_dict(u)) for u in session.query(UserModel).all()]
        finally:
            session.close()


class _DocumentsTable:
    """Drop-in replacement for the old `documents` dict, backed by SQLite."""

    def __setitem__(self, doc_id, value: dict):
        value = {k: v for k, v in value.items() if k != "document_id"}
        session = SessionLocal()
        try:
            existing = session.get(DocumentModel, doc_id)
            if existing:
                for k, v in value.items():
                    setattr(existing, k, v)
            else:
                session.add(DocumentModel(document_id=doc_id, **value))
            session.commit()
        finally:
            session.close()

    def __getitem__(self, doc_id):
        session = SessionLocal()
        try:
            d = session.get(DocumentModel, doc_id)
            if d is None:
                raise KeyError(doc_id)
            return _doc_to_dict(d)
        finally:
            session.close()

    def __contains__(self, doc_id):
        session = SessionLocal()
        try:
            return session.get(DocumentModel, doc_id) is not None
        finally:
            session.close()

    def items(self):
        session = SessionLocal()
        try:
            return [(d.document_id, _doc_to_dict(d)) for d in session.query(DocumentModel).all()]
        finally:
            session.close()


class _UserIdToUsername:
    """Drop-in replacement for user_id_to_username dict, backed by SQLite."""

    def __setitem__(self, user_id, username):
        pass  # no-op: user_id is already stored on the UserModel row itself

    def get(self, user_id, default=None):
        session = SessionLocal()
        try:
            u = session.query(UserModel).filter_by(user_id=user_id).first()
            return u.username if u else default
        finally:
            session.close()


users = _UsersTable()
documents = _DocumentsTable()
user_id_to_username = _UserIdToUsername()