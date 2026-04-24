"""
Secure Vault — SQLAlchemy Models
=================================
All sensitive data at rest is stored as encrypted blobs or
strings (ciphertext).  Private keys are NEVER persisted.

User Model  → owned by Role 1 (Identity Service)
Vault Model → owned by Role 3 (Hybrid Vault Service)
"""

from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """
    Stores user identity artefacts.

    Fields
    ------
    username         : RSA-encrypted username stored as hex string.
    password_hash    : Output of the custom iterative bit-shifting hash.
    salt             : Random salt used for the password hash.
    rsa_public_key   : JSON-serialised RSA public key  {"e": ..., "n": ...}.
    ecc_public_key   : JSON-serialised ECC public key  {"x": ..., "y": ...}.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, nullable=False)            # encrypted (hex ciphertext)
    password_hash = Column(String, nullable=False)       # custom hash output
    salt = Column(String, nullable=False)                # plaintext salt
    rsa_public_key = Column(String, nullable=False)      # JSON string
    ecc_public_key = Column(String, nullable=False)      # JSON string

    vaults = relationship("Vault", back_populates="owner")


class Vault(Base):
    """
    Stores a single encrypted note / file.

    Fields
    ------
    encrypted_payload       : IV + CBC-encrypted SPN blocks (raw bytes).
    encrypted_symmetric_key : Symmetric session key encrypted with the
                              owner's RSA public key (integer as string).
    digital_signature       : ECDSA signature over the payload MAC,
                              stored as JSON {"r": ..., "s": ...}.
    """
    __tablename__ = "vaults"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_payload = Column(LargeBinary, nullable=False)
    encrypted_symmetric_key = Column(String, nullable=False)
    digital_signature = Column(String, nullable=False)

    owner = relationship("User", back_populates="vaults")
