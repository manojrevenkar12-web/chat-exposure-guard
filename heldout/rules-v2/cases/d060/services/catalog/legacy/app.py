from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", methods=["GET"])


@app.get("/v0/characters/featured")
def featured():
    return jsonify({"characters": []})
