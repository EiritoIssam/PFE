"""
Authentication routes:
  POST /api/auth/register  — create account + RSA keypair
  POST /api/auth/login     — verify credentials → JWT
  GET  /api/auth/me        — return current user info
"""

from flask import Blueprint, request, jsonify, current_app
import jwt
import datetime

from backend.models import get_db, hash_password, verify_password
from backend.crypto.rsa_utils import generate_rsa_keypair

auth_bp = Blueprint("auth", __name__)


def make_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None


def require_auth(f):
    """Decorator — injects current_user_id and current_username into kwargs."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:]
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Token expired or invalid"}), 401
        kwargs["current_user_id"] = int(payload["sub"])
        kwargs["current_username"] = payload["username"]
        return f(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Generate RSA keypair — private key goes to client, public key stored in DB
    private_pem, public_pem = generate_rsa_keypair()

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, hash_password(password), public_pem),
        )
        db.commit()
        user_id = cur.lastrowid
    except Exception as e:
        db.close()
        if "UNIQUE" in str(e):
            return jsonify({"error": "Username already taken"}), 409
        return jsonify({"error": "Registration failed"}), 500
    finally:
        db.close()

    token = make_token(user_id, username)
    return jsonify({
        "message": "Account created successfully",
        "token": token,
        "user": {"id": user_id, "username": username},
        # Private key returned ONCE — client must save it locally
        "private_key": private_pem,
        "public_key": public_pem,
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    db.close()

    if not row or not verify_password(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = make_token(row["id"], row["username"])
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {"id": row["id"], "username": row["username"]},
    })


@auth_bp.route("/me", methods=["GET"])
@require_auth
def me(**kwargs):
    db = get_db()
    row = db.execute(
        "SELECT id, username, created_at FROM users WHERE id = ?",
        (kwargs["current_user_id"],),
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": row["id"], "username": row["username"], "created_at": row["created_at"]})
