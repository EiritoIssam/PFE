"""
SecureShare — Flask backend entry point.

Run:
    cd secure-share-app
    python -m backend.app

The API is available at http://localhost:5000/api/
"""

import os
from flask import Flask, send_from_directory
from backend.models import init_db
from backend.routes.auth import auth_bp
from backend.routes.files import files_bp
from backend.routes.users import users_bp
from flask_cors import CORS


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=os.path.join(os.path.dirname(__file__), "..", "frontend"),
        static_url_path="",
    )
    CORS(app)

    # ------------------------------------------------------------------ config
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod-!!-key")
    app.config["MAX_CONTENT_LENGTH"] = 52 * 1024 * 1024  # 52 MB

    # ------------------------------------------------------------------ CORS (manual, no flask-cors needed)
    

    @app.route("/<path:path>", methods=["OPTIONS"])
    def options_handler(path):
        from flask import Response
        return Response(status=200)

    # ------------------------------------------------------------------ blueprints
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(users_bp, url_prefix="/api/users")

    # ------------------------------------------------------------------ serve frontend
    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/dashboard")
    def dashboard():
        return send_from_directory(app.static_folder, "dashboard.html")

    # ------------------------------------------------------------------ DB
    init_db()

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True, host="0.0.0.0", port=5000)
