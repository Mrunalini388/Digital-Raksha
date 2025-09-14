# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import requests
import logging
from detector import analyze_url

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# VirusTotal API key comes from environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "4"))  # tune strictness

# Simple in-memory cache: {url: (expires_at_epoch, result_dict)}
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
        print("VirusTotal error:", e)
        return {"vt_checked": True, "vt_malicious": False, "vt_message": f"error: {e}"}

@app.route("/health")
def health():
    return {"status": "ok", "version": "2.0", "features": ["enhanced_detection", "threat_levels", "ml_support"]}

@app.route("/stats")
def stats():
    """Get server statistics"""
    return {
        "cache_size": len(SCAN_CACHE),
        "cache_ttl": SCAN_CACHE_TTL_SECONDS,
        "block_threshold": BLOCK_THRESHOLD,
        "virustotal_enabled": bool(VIRUSTOTAL_API_KEY),
        "uptime": time.time()
    }

@app.route("/config", methods=["GET", "POST"])
def config():
    """Get or update server configuration"""
    if request.method == "GET":
        return {
            "block_threshold": BLOCK_THRESHOLD,
            "cache_ttl": SCAN_CACHE_TTL_SECONDS,
            "virustotal_enabled": bool(VIRUSTOTAL_API_KEY)
        }
    else:
        # Update configuration
        data = request.get_json(force=True)
        global BLOCK_THRESHOLD, SCAN_CACHE_TTL_SECONDS
        
        if "block_threshold" in data:
            BLOCK_THRESHOLD = float(data["block_threshold"])
        if "cache_ttl" in data:
            SCAN_CACHE_TTL_SECONDS = int(data["cache_ttl"])
            
        return {"status": "updated", "config": {
            "block_threshold": BLOCK_THRESHOLD,
            "cache_ttl": SCAN_CACHE_TTL_SECONDS
        }}

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "").strip()
        if not url:
            logger.warning("Scan request missing URL")
            return jsonify({"error": "Missing 'url'"}), 400

        logger.info(f"Scanning URL: {url}")

        # Serve from cache when fresh
        now = time.time()
        cached = SCAN_CACHE.get(url)
        if cached and cached[0] > now:
            logger.info(f"Returning cached result for: {url}")
            return jsonify(cached[1]), 200

        # Analyze via our detector (rules + optional ML) -> provides score
        logger.info(f"Analyzing URL with enhanced detector: {url}")
        result = analyze_url(url)

    # VirusTotal scan (adds signal; if malicious, force unsafe)
    vt = check_virustotal(url)
    if vt.get("vt_checked"):
        result["virustotal"] = vt
        if vt.get("vt_malicious"):
            # High-weight signal
            result["score"] = max(result.get("score", 0), result.get("score", 0) + 6)
            threats = result.get("threats", []) + ["VirusTotal flagged"]
            result["threats"] = sorted(set(threats))
            result["threat_label"] = " / ".join(result["threats"]) if result["threats"] else "unsafe"

    # Enhanced decision logic with threat levels
    score = float(result.get("score", 0))
    risk_score = result.get("risk_score", score)
    confidence = result.get("confidence", 0.5)
    
    # Determine threat level based on risk score and confidence
    if risk_score >= 8 or (risk_score >= 6 and confidence >= 0.8):
        threat_level = "CRITICAL"
        result["safe"] = False
    elif risk_score >= 5 or (risk_score >= 3 and confidence >= 0.7):
        threat_level = "HIGH"
        result["safe"] = False
    elif risk_score >= 3 or (risk_score >= 1 and confidence >= 0.6):
        threat_level = "MEDIUM"
        result["safe"] = risk_score < 4  # Only block if very high risk
    elif risk_score >= 1:
        threat_level = "LOW"
        result["safe"] = True
    else:
        threat_level = "SAFE"
        result["safe"] = True
    
    # Update result with enhanced fields
    result["threat_level"] = threat_level
    result["risk_score"] = risk_score
    result["confidence"] = confidence
    
    # Generate appropriate message based on threat level
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

        # Store in cache
        SCAN_CACHE[url] = (now + SCAN_CACHE_TTL_SECONDS, result)
        logger.info(f"Scan completed for {url}: {result.get('threat_level', 'UNKNOWN')} - {result.get('safe', False)}")

        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error scanning URL {url}: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": "Failed to scan URL",
            "safe": False,
            "threat_level": "UNKNOWN",
            "threats": ["Scan failed"],
            "risk_score": 0,
            "confidence": 0
        }), 500

if __name__ == "__main__":
    # Get port from environment (for Google App Engine)
    port = int(os.environ.get("PORT", 5000))
    
    # Run in production mode for deployment
    if os.environ.get("GAE_ENV"):
        # Running on Google App Engine
        app.run(host="0.0.0.0", port=port, debug=False)
    else:
        # Running locally
        app.run(host="0.0.0.0", port=port, debug=True)









