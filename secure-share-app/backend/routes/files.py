"""
Files routes:
  POST   /api/files/upload              — upload encrypted file (client-side encryption)
  GET    /api/files/                    — list files owned by or shared with me
  POST   /api/files/<id>/share          — share file with another user
  GET    /api/files/<id>/key            — get encrypted AES key for my private key
  GET    /api/files/<id>/download       — download encrypted blob
  DELETE /api/files/<id>                — delete a file (owner only)
"""

import json
from flask import Blueprint, request, jsonify

from backend.models import get_db
from backend.routes.auth import require_auth

files_bp = Blueprint("files", __name__)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Upload  (client-side AES-GCM encryption, per-recipient RSA key wrapping)
# ---------------------------------------------------------------------------

@files_bp.route("/upload", methods=["POST"])
@require_auth
def upload_file(**kwargs):
    """
    Client encrypts the file with AES-256-GCM (Web Crypto).
    Client wraps the AES key with each recipient's RSA public key.
    Server stores: encrypted ciphertext, nonce, per-recipient wrapped AES keys.
    """
    user_id = kwargs["current_user_id"]

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = f.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        return jsonify({"error": f"File exceeds {MAX_FILE_SIZE // (1024*1024)} MB limit"}), 413
    if len(file_bytes) == 0:
        return jsonify({"error": "File is empty"}), 400

    # Nonce and wrapped keys come as form fields (set by client-side JS)
    nonce = request.form.get("nonce", "")
    if not nonce:
        return jsonify({"error": "Missing nonce"}), 400

    wrapped_keys_raw = request.form.get("wrapped_keys", "{}")
    try:
        wrapped_keys: dict = json.loads(wrapped_keys_raw)
    except Exception:
        return jsonify({"error": "Invalid wrapped_keys format"}), 400

    recipients_raw = request.form.get("recipients", "[]")
    try:
        recipient_ids = [int(r) for r in json.loads(recipients_raw)]
    except Exception:
        return jsonify({"error": "Invalid recipients format"}), 400

    if user_id not in recipient_ids:
        recipient_ids = [user_id] + recipient_ids

    # Encrypted file bytes are UTF-8 base64 string sent as file content
    try:
        encrypted_ciphertext = file_bytes.decode("utf-8")
    except Exception:
        encrypted_ciphertext = file_bytes.decode("latin-1")

    db = get_db()

    # Verify all recipient IDs exist
    placeholders = ",".join("?" * len(recipient_ids))
    user_rows = db.execute(
        f"SELECT id FROM users WHERE id IN ({placeholders})", recipient_ids
    ).fetchall()

    if len(user_rows) != len(recipient_ids):
        db.close()
        return jsonify({"error": "One or more recipient user IDs not found"}), 404

    try:
        with db:
            cur = db.execute(
                """INSERT INTO files (owner_id, filename, mimetype, file_size, encrypted_file, nonce)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, f.filename, f.mimetype or "application/octet-stream",
                 len(file_bytes), encrypted_ciphertext, nonce),
            )
            file_id = cur.lastrowid

            # Store per-recipient wrapped AES keys
            for uid in recipient_ids:
                enc_aes_key = wrapped_keys.get(str(uid))
                if enc_aes_key:
                    db.execute(
                        "INSERT INTO file_keys (file_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
                        (file_id, uid, enc_aes_key),
                    )
    except Exception as e:
        db.close()
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500
    finally:
        db.close()

    return jsonify({
        "message": "File uploaded and encrypted successfully",
        "file_id": file_id,
        "filename": f.filename,
        "size": len(file_bytes),
        "recipients": len(user_rows),
    }), 201


# ---------------------------------------------------------------------------
# List files
# ---------------------------------------------------------------------------

@files_bp.route("/", methods=["GET"])
@require_auth
def list_files(**kwargs):
    user_id = kwargs["current_user_id"]
    db = get_db()
    rows = db.execute(
        """SELECT f.id, f.filename, f.mimetype, f.file_size, f.uploaded_at,
                  u.username AS owner_name, f.owner_id,
                  CASE WHEN f.owner_id = :uid THEN 1 ELSE 0 END AS is_owner
           FROM files f
           JOIN users u ON u.id = f.owner_id
           JOIN file_keys fk ON fk.file_id = f.id
           WHERE fk.user_id = :uid
           ORDER BY f.uploaded_at DESC""",
        {"uid": user_id},
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Share file
# ---------------------------------------------------------------------------

@files_bp.route("/<int:file_id>/share", methods=["POST"])
@require_auth
def share_file(file_id: int, **kwargs):
    user_id = kwargs["current_user_id"]
    data = request.get_json(silent=True) or {}
    recipient_id = data.get("recipient_id")
    encrypted_aes_key = data.get("encrypted_aes_key")

    if not recipient_id or not encrypted_aes_key:
        return jsonify({"error": "recipient_id and encrypted_aes_key are required"}), 400

    db = get_db()
    row = db.execute("SELECT owner_id FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "File not found"}), 404
    if row["owner_id"] != user_id:
        db.close()
        return jsonify({"error": "Only the file owner can share this file"}), 403

    try:
        with db:
            db.execute(
                "INSERT OR REPLACE INTO file_keys (file_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
                (file_id, recipient_id, encrypted_aes_key),
            )
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

    return jsonify({"message": "File shared successfully"})


# ---------------------------------------------------------------------------
# Get encrypted AES key
# ---------------------------------------------------------------------------

@files_bp.route("/<int:file_id>/key", methods=["GET"])
@require_auth
def get_file_key(file_id: int, **kwargs):
    user_id = kwargs["current_user_id"]
    db = get_db()
    row = db.execute(
        "SELECT encrypted_aes_key FROM file_keys WHERE file_id = ? AND user_id = ?",
        (file_id, user_id),
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "Access denied or file not found"}), 403
    return jsonify({"encrypted_aes_key": row["encrypted_aes_key"]})


# ---------------------------------------------------------------------------
# Download encrypted blob
# ---------------------------------------------------------------------------

@files_bp.route("/<int:file_id>/download", methods=["GET"])
@require_auth
def download_file(file_id: int, **kwargs):
    user_id = kwargs["current_user_id"]
    db = get_db()
    access = db.execute(
        "SELECT 1 FROM file_keys WHERE file_id = ? AND user_id = ?", (file_id, user_id)
    ).fetchone()
    if not access:
        db.close()
        return jsonify({"error": "Access denied"}), 403

    row = db.execute(
        "SELECT filename, mimetype, encrypted_file, nonce FROM files WHERE id = ?", (file_id,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "File not found"}), 404

    return jsonify({
        "filename": row["filename"],
        "mimetype": row["mimetype"],
        "encrypted_file": row["encrypted_file"],
        "nonce": row["nonce"],
    })


# ---------------------------------------------------------------------------
# Delete file
# ---------------------------------------------------------------------------

@files_bp.route("/<int:file_id>", methods=["DELETE"])
@require_auth
def delete_file(file_id: int, **kwargs):
    user_id = kwargs["current_user_id"]
    db = get_db()
    row = db.execute("SELECT owner_id FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "File not found"}), 404
    if row["owner_id"] != user_id:
        db.close()
        return jsonify({"error": "Only the owner can delete this file"}), 403
    with db:
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.close()
    return jsonify({"message": "File deleted successfully"})
