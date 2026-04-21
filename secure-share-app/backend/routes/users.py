"""
Users routes:
  GET /api/users          — list all users (for share recipient selection)
  GET /api/users/<id>     — get a user's public key
"""

from flask import Blueprint, jsonify

from backend.models import get_db
from backend.routes.auth import require_auth

users_bp = Blueprint("users", __name__)


@users_bp.route("/", methods=["GET"])
@require_auth
def list_users(**kwargs):
    """Return all users except the currently logged-in one."""
    db = get_db()
    rows = db.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username",
        (kwargs["current_user_id"],),
    ).fetchall()
    db.close()
    return jsonify([{"id": r["id"], "username": r["username"]} for r in rows])


@users_bp.route("/<int:user_id>/public-key", methods=["GET"])
@require_auth
def get_public_key(user_id: int, **kwargs):
    """Return a user's RSA public key (used by uploader to wrap AES key)."""
    db = get_db()
    row = db.execute(
        "SELECT username, public_key FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user_id, "username": row["username"], "public_key": row["public_key"]})
