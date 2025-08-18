import re
import json
import socket
import requests
from urllib.parse import urlparse
from pathlib import Path

# ---------- Optional ML (loaded if present) ----------
# If you later train models locally and commit the files,
# these will be used automatically.
ML_DIR = Path(__file__).parent
URL_MODEL_PATH = ML_DIR / "model_url.joblib"          # optional
URL_FEATURE_ORDER = ML_DIR / "feature_order.json"     # optional
HTML_VECT_PATH = ML_DIR / "model_html_tfidf.joblib"   # optional
HTML_CLF_PATH  = ML_DIR / "model_html_clf.joblib"     # optional

_url_clf = None
_url_feat_order = None
_html_vect = None
_html_clf = None

def _lazy_import_ml():
    global _url_clf, _url_feat_order, _html_vect, _html_clf
    try:
        from joblib import load
        if URL_MODEL_PATH.exists():
            _url_clf = load(URL_MODEL_PATH)
        if URL_FEATURE_ORDER.exists():
            _url_feat_order = json.loads(URL_FEATURE_ORDER.read_text(encoding="utf-8"))
        if HTML_VECT_PATH.exists() and HTML_CLF_PATH.exists():
            _html_vect = load(HTML_VECT_PATH)
            _html_clf  = load(HTML_CLF_PATH)
    except Exception:
        # If anything fails, just run rule-based
        _url_clf = None
        _html_vect = None
        _html_clf = None

_lazy_import_ml()

# ---------- Simple malware blacklist (optional file) ----------
# Put suspicious domains (one per line) into malware_domains.txt if you have any.
BLACKLIST_FILE = ML_DIR / "malware_domains.txt"
BLACKLIST = set()
if BLACKLIST_FILE.exists():
    try:
        BLACKLIST = {
            line.strip().lower()
            for line in BLACKLIST_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    except Exception:
        BLACKLIST = set()

# ---------- Helpers ----------
def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""

def _is_ip(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except Exception:
        return False

def _extract_features_from_url(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return {
        "NumDots": url.count('.'),
        "SubdomainLevel": max(0, len(host.split('.')) - 2) if host else 0,
        "PathLevel": url.count('/'),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "NumDashInHostname": host.count('-') if host else 0,
        "AtSymbol": int('@' in url),
        "TildeSymbol": int('~' in url),
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": len(parsed.query.split('&')) if parsed.query else 0,
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": int(not url.lower().startswith('https://')),
        "RandomString": 0,  # placeholder
        "IpAddress": int(_is_ip(host)),
        "DomainInSubdomains": 0,
        "DomainInPaths": 0,
        "HttpsInHostname": int('https' in host.lower()),
        "HostnameLength": len(host),
        "PathLength": len(parsed.path or ""),
        "QueryLength": len(parsed.query or ""),
        "DoubleSlashInPath": int('//' in (parsed.path or "")),
        "NumSensitiveWords": 0,
        "EmbeddedBrandName": 0,
        "PctExtHyperlinks": 0,
        "PctExtResourceUrls": 0,
        "ExtFavicon": 0,
        "InsecureForms": 0,
        "RelativeFormAction": 0,
        "ExtFormAction": 0,
        "AbnormalFormAction": 0,
        "PctNullSelfRedirectHyperlinks": 0,
        "FrequentDomainNameMismatch": 0,
        "FakeLinkInStatusBar": 0,
        "RightClickDisabled": 0,
        "PopUpWindow": 0,
        "SubmitInfoToEmail": 0,
        "IframeOrFrame": 0,
        "MissingTitle": 0,
        "ImagesOnlyInForm": 0,
        "SubdomainLevelRT": 0,
        "UrlLengthRT": 0,
        "PctExtResourceUrlsRT": 0,
        "AbnormalExtFormActionR": 0,
        "ExtMetaScriptLinkRT": 0,
        "PctExtNullSelfRedirectHyperlinksRT": 0,
    }

def _fetch(url: str):
    try:
        # modest headers to avoid some blocks
        headers = {"User-Agent": "Mozilla/5.0 (DigitalRaksha/1.0)"}
        resp = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
        return resp
    except Exception:
        return None

def _nlp_rule_checks(html_text: str) -> list:
    """Lightweight rule-based NLP-ish checks – no external model download."""
    alerts = []
    text = (html_text or "").lower()

    # phishing words around forms
    if "<form" in text and any(w in text for w in ["password", "otp", "cvv", "ssn", "debit", "credit"]):
        alerts.append("Phishing form (asking for secrets)")

    # urgent language heuristics
    if any(p in text for p in ["verify your account", "update your account", "suspended", "unauthorized login"]):
        alerts.append("Deceptive/urgent language")

    # fake support scams
    if "microsoft support" in text or "windows support" in text:
        if any(w in text for w in ["call", "install", "download"]):
            alerts.append("Tech support scam patterns")
    return alerts

def analyze_url(url: str) -> dict:
    threats = []
    host = _hostname(url)

    # (A) HTTP only?
    if url.lower().startswith("http://"):
        threats.append("Insecure HTTP (no SSL)")

    # (B) Suspicious keywords in URL
    phishing_keywords = ["login", "verify", "secure", "update", "account", "bank", "wallet", "reset", "signin"]
    if any(k in url.lower() for k in phishing_keywords):
        threats.append("Phishing-like keywords in URL")

    # (C) Blacklist check
    if host and host.lower() in BLACKLIST:
        threats.append("Known malware/blacklist domain")

    # (D) Network fetch + redirects
    resp = _fetch(url)
    if not resp:
        threats.append("Unreachable or blocked")
    else:
        if resp.history and len(resp.history) > 0:
            threats.append("Redirect chain detected")

        # (E) Rule-based NLP on HTML
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" in ctype:
            threats.extend(_nlp_rule_checks(resp.text))

    # (F) Optional ML: URL structured model
    try:
        if _url_clf and _url_feat_order:
            feats = _extract_features_from_url(url)
            row = [[feats.get(col, 0) for col in _url_feat_order]]
            pred = int(_url_clf.predict(row)[0])
            if pred == 1:
                threats.append("ML: Phishing (URL model)")
    except Exception:
        # if anything goes wrong, ignore ML and keep rule-based results
        pass

    # (G) Optional ML: HTML content model (TF-IDF + classifier)
    try:
        if resp and _html_vect and _html_clf and "text/html" in (resp.headers.get("Content-Type") or "").lower():
            X = _html_vect.transform([resp.text])
            pred_html = int(_html_clf.predict(X)[0])
            if pred_html == 1:
                threats.append("ML: Malicious content (HTML model)")
    except Exception:
        pass

    threats = sorted(set(threats))
    safe = (len(threats) == 0)
    message = "✅ Safe browsing!" if safe else f"🚨 Digital Raksha Alert: {', '.join(threats)}"

    # For awareness voice/text in frontend, also include a friendly label
    threat_label = "safe" if safe else " / ".join(threats)

    return {
        "url": url,
        "hostname": host,
        "safe": safe,
        "threats": threats,
        "message": message,
        "threat_label": threat_label
    }

