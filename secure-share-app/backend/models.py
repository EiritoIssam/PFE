"""
Database models and initialization for SecureShare.

Schema:
  users       — user accounts + public RSA key
  files       — encrypted file blobs + metadata
  file_keys   — per-recipient encrypted AES keys (one row per share)
"""

import sqlite3
import hashlib
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "database.db"


def get_db() -> sqlite3.Connection:
    """Open a DB connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create all tables if they don't exist."""
    conn = get_db()
    with conn:
        conn.executescript("""
            -- -------------------------------------------------------
            -- Users: stores credentials + public RSA key
            -- Private key is NEVER stored here — client keeps it.
            -- -------------------------------------------------------
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                password_hash TEXT  NOT NULL,          -- SHA-256(password)
                public_key  TEXT    NOT NULL,           -- PEM RSA-2048 public key
                created_at  DATETIME DEFAULT (datetime('now'))
            );

            -- -------------------------------------------------------
            -- Files: stores the AES-GCM encrypted file + metadata
            -- The raw file bytes are NEVER stored in plaintext.
            -- -------------------------------------------------------
            CREATE TABLE IF NOT EXISTS files (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename        TEXT    NOT NULL,       -- original filename
                mimetype        TEXT    NOT NULL DEFAULT 'application/octet-stream',
                file_size       INTEGER NOT NULL,       -- original size in bytes
                encrypted_file  BLOB    NOT NULL,       -- AES-256-GCM ciphertext
                nonce           TEXT    NOT NULL,       -- base64 GCM nonce
                uploaded_at     DATETIME DEFAULT (datetime('now'))
            );

            -- -------------------------------------------------------
            -- File keys: per-recipient AES key wrapped with RSA
            -- One row per (file, recipient) pair.
            -- -------------------------------------------------------
            CREATE TABLE IF NOT EXISTS file_keys (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                encrypted_aes_key TEXT  NOT NULL,      -- base64 RSA-OAEP(AES key)
                shared_at       DATETIME DEFAULT (datetime('now')),
                UNIQUE (file_id, user_id)
            );
        """)
    conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """SHA-256 hash a password with a per-user salt (stored as hex:hash)."""
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(stored: str, password: str) -> bool:
    """Verify a password against a stored salt:hash string."""
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False
