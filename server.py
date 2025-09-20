# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import requests
import logging
from detector import analyze_url

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "4"))
SCAN_CACHE_TTL_SECONDS = int(os.getenv("SCAN_CACHE_TTL", "300"))
SCAN_CACHE = {}

def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"vt_checked": False, "vt_malicious": False, "vt_message": "VIRUSTOTAL_API_KEY not set"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        data = resp.json()
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        return {"vt_checked": True, "vt_malicious": malicious_count > 0, "vt_message": "ok"}
    except Exception as e:
        logger.error("VirusTotal error: %s", e)
        return {"vt_checked": True, "vt_malicious": False, "vt_message": f"error: {e}"}

@app.route("/health")
def health():
    return {"status": "ok", "version": "2.0"}

@app.route("/stats")
def stats():
    return {
        "cache_size": len(SCAN_CACHE),
        "cache_ttl": SCAN_CACHE_TTL_SECONDS,
        "block_threshold": BLOCK_THRESHOLD,
        "virustotal_enabled": bool(VIRUSTOTAL_API_KEY),
        "uptime": time.time()
    }

@app.route("/config", methods=["GET", "POST"])
def config():
    global BLOCK_THRESHOLD, SCAN_CACHE_TTL_SECONDS
    if request.method == "GET":
        return {"block_threshold": BLOCK_THRESHOLD, "cache_ttl": SCAN_CACHE_TTL_SECONDS, "virustotal_enabled": bool(VIRUSTOTAL_API_KEY)}
    data = request.get_json(force=True)
    if "block_threshold" in data:
        BLOCK_THRESHOLD = float(data["block_threshold"])
    if "cache_ttl" in data:
        SCAN_CACHE_TTL_SECONDS = int(data["cache_ttl"])
    return {"status": "updated", "config": {"block_threshold": BLOCK_THRESHOLD, "cache_ttl": SCAN_CACHE_TTL_SECONDS}}

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        now = time.time()
        cached = SCAN_CACHE.get(url)
        if cached and cached[0] > now:
            return jsonify(cached[1]), 200

        # Main detection
        result = analyze_url(url)

        # VirusTotal safely wrapped
        try:
            vt = check_virustotal(url)
            if vt.get("vt_checked"):
                result["virustotal"] = vt
                if vt.get("vt_malicious"):
                    result["score"] = max(result.get("score", 0), result.get("score", 0) + 6)
                    threats = result.get("threats", []) + ["VirusTotal flagged"]
                    result["threats"] = sorted(set(threats))
                    result["threat_label"] = " / ".join(result["threats"]) if result["threats"] else "unsafe"
        except Exception as e:
            logger.error("VirusTotal check failed: %s", e)

        # Threat evaluation
        score = float(result.get("score", 0))
        risk_score = result.get("risk_score", score)
        confidence = result.get("confidence", 0.5)

        if risk_score >= 8 or (risk_score >= 6 and confidence >= 0.8):
            threat_level = "CRITICAL"
            result["safe"] = False
        elif risk_score >= 5 or (risk_score >= 3 and confidence >= 0.7):
            threat_level = "HIGH"
            result["safe"] = False
        elif risk_score >= 3 or (risk_score >= 1 and confidence >= 0.6):
            threat_level = "MEDIUM"
            result["safe"] = risk_score < 4
        elif risk_score >= 1:
            threat_level = "LOW"
            result["safe"] = True
        else:
            threat_level = "SAFE"
            result["safe"] = True

        result["threat_level"] = threat_level
        result["risk_score"] = risk_score
        result["confidence"] = confidence

        # Message
        if not result["safe"]:
            if threat_level == "CRITICAL":
                result["message"] = f"🚨 CRITICAL THREAT: {', '.join(result.get('threats', [])) or 'Dangerous site detected'}"
            elif threat_level == "HIGH":
                result["message"] = f"⚠️ HIGH RISK: {', '.join(result.get('threats', [])) or 'Unsafe site detected'}"
            else:
                result["message"] = f"⚡ MEDIUM RISK: {', '.join(result.get('threats', [])) or 'Suspicious site detected'}"
        else:
            if threat_level == "LOW":
                result["message"] = f"ℹ️ LOW RISK: {', '.join(result.get('threats', [])) or 'Minor security concerns detected'}"
            else:
                result["message"] = "✅ Safe browsing!"

        # Cache
        SCAN_CACHE[url] = (now + SCAN_CACHE_TTL_SECONDS, result)
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return jsonify({"error": "Internal server error", "safe": False, "threat_level": "UNKNOWN"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)










