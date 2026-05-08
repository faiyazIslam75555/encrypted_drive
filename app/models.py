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
    Stores user identity artefacts. All data at rest is RSA-encrypted.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username_encrypted = Column(String, nullable=False)     # RSA-encrypted hex
    email_encrypted = Column(String, nullable=False)        # RSA-encrypted hex
    password_hash = Column(String, nullable=False)          # Scratch hash
    salt = Column(String, nullable=False)                   
    rsa_public_key = Column(String, nullable=False)         # JSON string
    ecc_public_key = Column(String, nullable=False)         # JSON string
    role = Column(String, nullable=False, default="user")   # "user" or "admin"
    created_at = Column(String, nullable=False)

    vaults = relationship("Vault", back_populates="owner", cascade="all, delete-orphan")


class Vault(Base):
    """
    Stores purely asymmetric encrypted file chunks.
    """
    __tablename__ = "vaults"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename_encrypted = Column(String, nullable=False)      # RSA/ECC encrypted
    encrypted_payload = Column(String, nullable=False)       # Multi-chunk RSA/ECC string
    digital_signature = Column(String, nullable=False)       # ECC Signature JSON
    mac_hash = Column(String, nullable=False)                # Scratch Hash
    uploaded_at = Column(String, nullable=False)

    owner = relationship("User", back_populates="vaults")
    shares = relationship("SharedFile", back_populates="vault", cascade="all, delete-orphan")


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
