# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import scan_url_full

app = Flask(__name__)
CORS(app)

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400
    return jsonify(scan_url_full(url)), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

