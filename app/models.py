"""
Secure Vault — SQLAlchemy Models
=================================
All sensitive data at rest is stored as encrypted blobs or
strings (ciphertext).  Private keys are NEVER persisted.

User Model       → owned by Role 1 (Identity Service)
Vault Model      → owned by Role 3 (Hybrid Vault Service)
SharedFile Model → file sharing between users
"""

from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """
    Stores user identity artefacts.

    Fields
    ------
    username_encrypted : RSA-encrypted username stored as hex string.
    email_encrypted    : RSA-encrypted email stored as hex string.
    password_hash      : Output of the custom iterative bit-shifting hash.
    salt               : Random salt used for the password hash.
    rsa_public_key     : JSON-serialised RSA public key  {"e": ..., "n": ...}.
    ecc_public_key     : JSON-serialised ECC public key  {"x": ..., "y": ...}.
    role               : "user" or "admin".
    created_at         : ISO-format timestamp string.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username_encrypted = Column(String, nullable=False)     # RSA-encrypted (hex)
    email_encrypted = Column(String, nullable=False)        # RSA-encrypted (hex)
    password_hash = Column(String, nullable=False)          # custom hash output
    salt = Column(String, nullable=False)                   # plaintext salt
    rsa_public_key = Column(String, nullable=False)         # JSON string
    ecc_public_key = Column(String, nullable=False)         # JSON string
    role = Column(String, nullable=False, default="user")   # "user" or "admin"
    created_at = Column(String, nullable=False)             # ISO timestamp

    vaults = relationship("Vault", back_populates="owner",
                          cascade="all, delete-orphan")


class Vault(Base):
    """
    Stores a single encrypted file.

    Fields
    ------
    filename_encrypted      : Filename encrypted with ECC (JSON blob).
    file_size               : Original file size in bytes.
    encrypted_payload       : IV + CBC-encrypted SPN blocks (raw bytes).
    encrypted_symmetric_key : Session key encrypted with the
                              owner's ECC public key (JSON string).
    digital_signature       : ECDSA signature over the payload hash,
                              stored as JSON {"r": ..., "s": ...}.
    mac_hash                : The hash value used for MAC (hex string).
    uploaded_at             : ISO-format timestamp string.
    """
    __tablename__ = "vaults"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename_encrypted = Column(String, nullable=False)     # ECC-encrypted filename
    file_size = Column(Integer, nullable=False, default=0)
    encrypted_payload = Column(LargeBinary, nullable=False)
    encrypted_symmetric_key = Column(String, nullable=False)
    digital_signature = Column(String, nullable=False)
    mac_hash = Column(String, nullable=False)
    uploaded_at = Column(String, nullable=False)

    owner = relationship("User", back_populates="vaults")
    shares = relationship("SharedFile", back_populates="vault",
                          cascade="all, delete-orphan")


class SharedFile(Base):
    """
    Tracks file sharing between users.

    The symmetric session key is re-encrypted with the
    recipient's ECC public key.
    """
    __tablename__ = "shared_files"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vault_id = Column(Integer, ForeignKey("vaults.id"), nullable=False)
    shared_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    shared_with = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_symmetric_key = Column(String, nullable=False)
    created_at = Column(String, nullable=False)

    vault = relationship("Vault", back_populates="shares")
