from flask import Flask, request, jsonify
from flask_cors import CORS
import requests, re, time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import joblib

# --------- Config ---------
REQUEST_TIMEOUT = 6
USER_AGENT = "DigitalRaksha/1.0 (+https://example.local)"

app = Flask(__name__)
CORS(app)

# --------- Load NLP model (created by train_nlp_model.py) ---------
# Creates nlp_model.pkl at build time or you can create it locally first.
MODEL_PATH = "nlp_model.pkl"
try:
    nlp_clf = joblib.load(MODEL_PATH)
except Exception as e:
    nlp_clf = None
    print("WARNING: NLP model not loaded:", e)

# --------- Helpers ---------
def fetch_page(url: str) -> str:
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        ct = resp.headers.get("Content-Type", "")
        if "text/html" in ct.lower():
            return resp.text or ""
        return ""
    except Exception:
        return ""

def get_title(html: str) -> str:
    try:
        if not html:
            return ""
        soup = BeautifulSoup(html, "html.parser")
        return (soup.title.string or "").strip() if soup.title else ""
    except Exception:
        return ""

def has_redirects(url: str) -> bool:
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        return len(r.history) > 0
    except Exception:
        return False

def is_http_not_https(url: str) -> bool:
    return url.lower().startswith("http://")

def basic_malware_heuristics(text: str) -> bool:
    # Very light heuristic (you can expand later)
    keywords = [
        "trojan", "spyware", "ransomware", "malware",
        "download.exe", "infected", "payload"
    ]
    text_lc = text.lower()
    return any(kw in text_lc for kw in keywords)

def url_text_repr(url: str, html: str) -> str:
    """
    Build the NLP "document" using URL, domain parts, page title, and a tiny slice of page text.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(url)
    title = get_title(html)
    text_snippet = ""
    if html:
        # remove script/style crud and compress whitespace
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.extract()
        text_snippet = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:1200]

    doc = " ".join([
        url,
        host.replace(".", " "),
        ext.domain or "",
        ext.suffix or "",
        title or "",
        text_snippet
    ])
    return doc

# --------- Routes ---------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "running",
        "message": "POST JSON to /predict-url like {\"url\":\"http://example.com\"}"
    })

@app.route("/predict-url", methods=["POST"])
def predict_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400

    threats = []
    t0 = time.time()

    # Fetch page (optional, but helps NLP)
    html = fetch_page(url)

    # NLP phishing score
    phishing_score = 0.0
    phishing_label = "unknown"
    if nlp_clf:
        doc = url_text_repr(url, html)
        try:
            proba = nlp_clf.predict_proba([doc])[0]  # [safe, phishing]
            phishing_score = float(proba[1])
            pred = nlp_clf.predict([doc])[0]
            phishing_label = "phishing" if int(pred) == 1 else "safe"
            if int(pred) == 1:
                threats.append("phishing")
        except Exception:
            phishing_label = "error"
    else:
        phishing_label = "model_not_loaded"

    # HTTP (no HTTPS)
    if is_http_not_https(url):
        threats.append("http-not-secure")

    # Redirects
    if has_redirects(url):
        threats.append("redirect")

    # Simple malware heuristic on HTML/text
    if basic_malware_heuristics(html):
        threats.append("malware")

    safe = len(threats) == 0
    elapsed_ms = int((time.time() - t0) * 1000)

    return jsonify({
        "url": url,
        "safe": safe,
        "threats": sorted(list(set(threats))),
        "nlp": {
            "label": phishing_label,
            "phishing_score": round(phishing_score, 4)
        },
        "perf_ms": elapsed_ms
    })

if __name__ == "__main__":
    # Local dev
    app.run(host="0.0.0.0", port=5000, debug=True)

