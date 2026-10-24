from flask import Flask, jsonify

from .auth import staff_required
from .config import DATABASE_URL
from .export import export_user_data

app = Flask(__name__)


@app.post("/internal/exports/<user_id>")
@staff_required
def start_export(user_id):
    path = export_user_data(DATABASE_URL, user_id)
    return jsonify({"archive": path}), 201
