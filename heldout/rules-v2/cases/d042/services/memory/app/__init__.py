from flask import Flask, abort, g, request
from flask_cors import CORS
from jose import jwt

from .views import bp as memories_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_prefixed_env("MEMORY")

    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

    @app.before_request
    def load_user():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            abort(401)
        claims = jwt.get_unverified_claims(header[7:])
        g.user_id = int(claims["sub"])
        g.scopes = set(claims.get("scope", "").split())

    app.register_blueprint(memories_bp)
    return app
