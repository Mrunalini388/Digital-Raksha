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

def _detect_typosquatting(hostname: str) -> dict:
    """Detect potential typosquatting patterns in domain names."""
    if not hostname:
        return {"is_typosquatting": False, "confidence": 0, "reasons": []}
    
    reasons = []
    confidence = 0
    
    # Common typosquatting patterns
    suspicious_patterns = [
        # Character substitutions
        r'[0-9]',  # Numbers in domain
        r'[^a-zA-Z0-9.-]',  # Special characters
        r'-{2,}',  # Multiple consecutive hyphens
        r'\.{2,}',  # Multiple consecutive dots
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, hostname):
            reasons.append(f"Suspicious characters: {pattern}")
            confidence += 1
    
    # Check for very long domain names
    if len(hostname) > 25:
        reasons.append("Unusually long domain name")
        confidence += 1
    
    # Check for excessive hyphens
    if hostname.count('-') > 3:
        reasons.append("Excessive hyphens in domain")
        confidence += 1
    
    # Check for mixed case (uncommon in legitimate domains)
    if hostname != hostname.lower() and hostname != hostname.upper():
        reasons.append("Mixed case domain (unusual)")
        confidence += 0.5
    
    # Check for common typosquatting suffixes/prefixes
    typosquatting_indicators = [
        'secure-', 'safe-', 'verify-', 'update-', 'confirm-',
        '-secure', '-safe', '-verify', '-update', '-confirm',
        'www-', 'secure-www', 'safe-www'
    ]
    
    for indicator in typosquatting_indicators:
        if indicator in hostname.lower():
            reasons.append(f"Typosquatting indicator: {indicator}")
            confidence += 1
    
    return {
        "is_typosquatting": confidence >= 2,
        "confidence": min(confidence, 5) / 5,  # Normalize to 0-1
        "reasons": reasons
    }

def _analyze_domain_reputation(hostname: str) -> dict:
    """Analyze domain reputation and characteristics."""
    if not hostname:
        return {"reputation_score": 0, "flags": []}
    
    flags = []
    score = 0
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.exe', '.zip']
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    if tld in suspicious_tlds:
        flags.append(f"Suspicious TLD: {tld}")
        score -= 2
    
    # Check for very short domains (often suspicious)
    if len(hostname) < 5:
        flags.append("Very short domain name")
        score -= 1
    
    # Check for random-looking domains
    if len(hostname) > 10 and sum(c.isdigit() for c in hostname) > len(hostname) * 0.3:
        flags.append("Random-looking domain (high digit ratio)")
        score -= 1
    
    # Check for common legitimate TLDs
    legitimate_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int']
    if tld in legitimate_tlds:
        score += 1
    
    # Check for subdomain patterns
    parts = hostname.split('.')
    if len(parts) > 3:  # Too many subdomains
        flags.append("Excessive subdomains")
        score -= 1
    
    return {
        "reputation_score": max(score, -5),  # Cap at -5
        "flags": flags
    }

def _check_url_structure(url: str) -> dict:
    """Analyze URL structure for suspicious patterns."""
    flags = []
    score = 0
    
    # Check for excessive encoding
    encoded_chars = url.count('%')
    if encoded_chars > 5:
        flags.append("Excessive URL encoding")
        score -= 1
    
    # Check for suspicious parameters
    if '?' in url:
        query = url.split('?')[1] if '?' in url else ''
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'next', 'continue', 'return']
        if any(param in query.lower() for param in suspicious_params):
            flags.append("Suspicious redirect parameters")
            score -= 2
    
    # Check for IP addresses in URL
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url):
        flags.append("IP address in URL")
        score -= 2
    
    # Check for port numbers (often suspicious)
    if ':' in url and re.search(r':\d+', url):
        flags.append("Port number in URL")
        score -= 1
    
    return {
        "structure_score": max(score, -5),
        "flags": flags
    }

def _extract_features_from_url(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    # Enhanced feature extraction
    sensitive_words = ["login", "verify", "secure", "update", "account", "bank", "wallet", "reset", "signin", "password", "otp", "cvv", "ssn", "debit", "credit", "paypal", "amazon", "apple", "google", "microsoft", "facebook", "twitter", "instagram", "linkedin", "netflix", "spotify", "uber", "airbnb"]
    
    # Count sensitive words in different parts of URL
    url_lower = url.lower()
    path_lower = path.lower()
    query_lower = query.lower()
    
    num_sensitive_words = sum(1 for word in sensitive_words if word in url_lower)
    num_sensitive_in_path = sum(1 for word in sensitive_words if word in path_lower)
    num_sensitive_in_query = sum(1 for word in sensitive_words if word in query_lower)
    
    # Check for brand names embedded in domain
    brand_names = ["paypal", "amazon", "apple", "google", "microsoft", "facebook", "twitter", "instagram", "linkedin", "netflix", "spotify", "uber", "airbnb", "ebay", "walmart", "target", "bestbuy", "homedepot", "lowes", "costco", "samsclub", "macys", "nordstrom", "gap", "oldnavy", "bananarepublic", "athleta", "jcrew", "annetaylor", "loft", "express", "hollister", "abercrombie", "american eagle", "aeropostale", "forever21", "zara", "h&m", "uniqlo", "asos", "boohoo", "shein", "fashion nova", "pretty little thing", "missguided", "nasty gal", "revolve", "shopbop", "net-a-porter", "farfetch", "ssense", "matchesfashion", "mytheresa", "luisaviaroma", "24s", "selfridges", "harrods", "liberty", "browns", "harvey nichols", "john lewis", "debenhams", "house of fraser", "marks and spencer", "next", "river island", "topshop", "topman", "new look", "primark", "asda", "tesco", "sainsburys", "morrisons", "waitrose", "aldi", "lidl", "iceland", "coop", "spar", "budgens", "nisa", "costcutter", "one stop", "mccolls", "post office", "w h smith", "boots", "superdrug", "lloyds pharmacy", "well pharmacy", "independent pharmacy", "pharmacy2u", "pharmacy online", "chemist direct", "pharmacy2home", "pharmacy2u", "pharmacy online", "chemist direct", "pharmacy2home"]
    
    embedded_brand = 0
    for brand in brand_names:
        if brand in host.lower():
            embedded_brand = 1
            break
    
    # Check for suspicious patterns
    suspicious_patterns = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "v.gd", "short.link", "tiny.cc", "shorturl.at", "cutt.ly", "short.link", "rebrand.ly", "shorturl.com", "tinyurl.com", "bitly.com", "goo.gl", "t.co", "ow.ly", "is.gd", "v.gd", "short.link", "tiny.cc", "shorturl.at", "cutt.ly", "short.link", "rebrand.ly", "shorturl.com"]
    
    is_shortened = 1 if any(pattern in host.lower() for pattern in suspicious_patterns) else 0
    
    # Check for typosquatting patterns
    typosquatting_indicators = 0
    if host:
        # Check for character substitutions
        if any(char in host for char in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']):
            typosquatting_indicators += 1
        # Check for extra characters
        if len(host) > 20:  # Very long domain names are suspicious
            typosquatting_indicators += 1
        # Check for multiple hyphens
        if host.count('-') > 2:
            typosquatting_indicators += 1
    
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
        "NumQueryComponents": len(query.split('&')) if query else 0,
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": int(not url.lower().startswith('https://')),
        "RandomString": int(len(host) > 15 and sum(c.isdigit() for c in host) > 3),  # Random-looking strings
        "IpAddress": int(_is_ip(host)),
        "DomainInSubdomains": int(any(brand in host.lower() for brand in brand_names)),
        "DomainInPaths": int(any(brand in path_lower for brand in brand_names)),
        "HttpsInHostname": int('https' in host.lower()),
        "HostnameLength": len(host),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": int('//' in path),
        "NumSensitiveWords": num_sensitive_words,
        "EmbeddedBrandName": embedded_brand,
        "PctExtHyperlinks": 0,  # Will be filled from HTML analysis
        "PctExtResourceUrls": 0,  # Will be filled from HTML analysis
        "ExtFavicon": 0,  # Will be filled from HTML analysis
        "InsecureForms": 0,  # Will be filled from HTML analysis
        "RelativeFormAction": 0,  # Will be filled from HTML analysis
        "ExtFormAction": 0,  # Will be filled from HTML analysis
        "AbnormalFormAction": 0,  # Will be filled from HTML analysis
        "PctNullSelfRedirectHyperlinks": 0,  # Will be filled from HTML analysis
        "FrequentDomainNameMismatch": 0,  # Will be filled from HTML analysis
        "FakeLinkInStatusBar": 0,  # Will be filled from HTML analysis
        "RightClickDisabled": 0,  # Will be filled from HTML analysis
        "PopUpWindow": 0,  # Will be filled from HTML analysis
        "SubmitInfoToEmail": 0,  # Will be filled from HTML analysis
        "IframeOrFrame": 0,  # Will be filled from HTML analysis
        "MissingTitle": 0,  # Will be filled from HTML analysis
        "ImagesOnlyInForm": 0,  # Will be filled from HTML analysis
        "SubdomainLevelRT": max(0, len(host.split('.')) - 2) if host else 0,
        "UrlLengthRT": len(url),
        "PctExtResourceUrlsRT": 0,  # Will be filled from HTML analysis
        "AbnormalExtFormActionR": 0,  # Will be filled from HTML analysis
        "ExtMetaScriptLinkRT": 0,  # Will be filled from HTML analysis
        "PctExtNullSelfRedirectHyperlinksRT": 0,  # Will be filled from HTML analysis
        # New enhanced features
        "IsShortenedUrl": is_shortened,
        "TyposquattingIndicators": typosquatting_indicators,
        "SensitiveWordsInPath": num_sensitive_in_path,
        "SensitiveWordsInQuery": num_sensitive_in_query,
        "HasSuspiciousChars": int(any(char in host for char in ['-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])),
        "PathToQueryRatio": len(path) / max(1, len(query)),
        "HostnameToUrlRatio": len(host) / max(1, len(url)),
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
    """Enhanced rule-based NLP checks with better accuracy and fewer false positives."""
    alerts = []
    text = (html_text or "").lower()

    # Enhanced phishing form detection
    if "<form" in text:
        sensitive_fields = ["password", "otp", "cvv", "ssn", "debit", "credit", "pin", "ssn", "social security", "bank account", "routing number", "card number", "expiry", "cvc", "cvv2", "security code"]
        urgent_phrases = ["verify immediately", "update now", "suspended", "unauthorized", "security breach", "account locked", "verify identity", "confirm details", "urgent action required"]
        
        has_sensitive_fields = any(field in text for field in sensitive_fields)
        has_urgent_language = any(phrase in text for phrase in urgent_phrases)
        
        if has_sensitive_fields and has_urgent_language:
            alerts.append("High-risk phishing form (sensitive data + urgency)")
        elif has_sensitive_fields:
            alerts.append("Suspicious form requesting sensitive data")

    # Enhanced urgent language detection
    urgent_patterns = [
        "verify your account", "update your account", "suspended", "unauthorized login",
        "security alert", "immediate action", "account will be closed", "verify identity",
        "confirm your information", "urgent verification", "account compromised",
        "suspicious activity", "verify payment", "confirm transaction"
    ]
    
    if any(pattern in text for pattern in urgent_patterns):
        alerts.append("Deceptive/urgent language detected")

    # Enhanced tech support scam detection
    tech_support_indicators = [
        "microsoft support", "windows support", "apple support", "google support",
        "facebook support", "amazon support", "paypal support", "bank support"
    ]
    
    scam_actions = ["call now", "install software", "download tool", "remote access", "fix computer", "virus detected", "system error", "critical update"]
    
    if any(tech in text for tech in tech_support_indicators):
        if any(action in text for action in scam_actions):
            alerts.append("Tech support scam patterns detected")

    # Check for suspicious redirects and pop-ups
    if "window.location" in text or "document.location" in text:
        if any(phrase in text for phrase in ["redirect", "forward", "go to", "navigate to"]):
            alerts.append("Suspicious redirect behavior")

    # Check for hidden elements (common in phishing)
    if "display:none" in text or "visibility:hidden" in text:
        if any(field in text for field in ["password", "credit", "ssn", "bank"]):
            alerts.append("Hidden sensitive form elements")

    # Check for suspicious JavaScript
    js_patterns = ["eval(", "document.write", "innerHTML", "outerHTML"]
    if any(pattern in text for pattern in js_patterns):
        if any(suspicious in text for suspicious in ["password", "login", "credit", "bank"]):
            alerts.append("Suspicious JavaScript with sensitive data")

    # Check for fake security indicators
    fake_security = ["secure connection", "verified site", "trusted site", "safe to proceed"]
    if any(phrase in text for phrase in fake_security):
        if not any(real_security in text for real_security in ["https://", "ssl", "tls", "encrypted"]):
            alerts.append("Fake security indicators without real encryption")

    # Check for suspicious email patterns
    if "email" in text and any(phrase in text for phrase in ["verify email", "confirm email", "update email", "change email"]):
        if any(suspicious in text for suspicious in ["urgent", "immediately", "suspended", "locked"]):
            alerts.append("Suspicious email verification request")

    return alerts

ALLOWLIST = {
    "youtube.com", "www.youtube.com", "youtu.be",
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "x.com", "www.twitter.com", "www.x.com",
    "wikipedia.org", "www.wikipedia.org"
}

def analyze_url(url: str) -> dict:
    threats = []
    evidence = []  # list of {label, weight, confidence}
    host = _hostname(url)
    confidence_scores = []

    # (A) HTTP only?
    if url.lower().startswith("http://"):
        threats.append("Insecure HTTP (no SSL)")
        evidence.append({"label": "insecure_http", "weight": 2, "confidence": 0.9})
        confidence_scores.append(0.9)

    # (B) Allowlist: widely trusted domains should not be flagged by heuristics
    if host.lower() in ALLOWLIST:
        # Still check for basic security issues even on allowlisted domains
        pass
    else:
        # Enhanced phishing detection with better accuracy
        parsed = urlparse(url)
        pq = (parsed.path or "") + "?" + (parsed.query or "")
        pq_lower = pq.lower()
        
        # More sophisticated phishing keyword detection
        phishing_keywords = ["login", "verify", "secure", "update", "account", "bank", "wallet", "reset", "signin", "password", "otp", "cvv", "ssn"]
        keyword_matches = [k for k in phishing_keywords if k in pq_lower]
        
        if keyword_matches:
            # Check if it's a legitimate use case
            legitimate_indicators = ["support", "help", "contact", "about", "privacy", "terms"]
            has_legitimate_context = any(indicator in pq_lower for indicator in legitimate_indicators)
            
            if not has_legitimate_context:
                threats.append(f"Phishing-like keywords in URL: {', '.join(keyword_matches[:3])}")
                evidence.append({"label": "phishing_keywords", "weight": 2, "confidence": 0.7})
                confidence_scores.append(0.7)

    # (C) Blacklist check
    if host and host.lower() in BLACKLIST:
        threats.append("Known malware/blacklist domain")
        evidence.append({"label": "blacklist_domain", "weight": 5, "confidence": 0.95})
        confidence_scores.append(0.95)

    # (D) Advanced domain analysis
    typosquatting_analysis = _detect_typosquatting(host)
    if typosquatting_analysis["is_typosquatting"]:
        threats.append(f"Potential typosquatting: {', '.join(typosquatting_analysis['reasons'][:2])}")
        evidence.append({"label": "typosquatting", "weight": 3, "confidence": typosquatting_analysis["confidence"]})
        confidence_scores.append(typosquatting_analysis["confidence"])

    # Domain reputation analysis
    reputation_analysis = _analyze_domain_reputation(host)
    if reputation_analysis["reputation_score"] < -2:
        threats.append(f"Low domain reputation: {', '.join(reputation_analysis['flags'][:2])}")
        evidence.append({"label": "low_reputation", "weight": 2, "confidence": 0.6})
        confidence_scores.append(0.6)

    # URL structure analysis
    structure_analysis = _check_url_structure(url)
    if structure_analysis["structure_score"] < -2:
        threats.append(f"Suspicious URL structure: {', '.join(structure_analysis['flags'][:2])}")
        evidence.append({"label": "suspicious_structure", "weight": 2, "confidence": 0.7})
        confidence_scores.append(0.7)

    # (E) Network fetch + redirects
    resp = _fetch(url)
    if not resp:
        # Do not mark unsafe solely due to unreachability; keep as info
        threats.append("Unreachable or blocked (info)")
    else:
        if resp.history and len(resp.history) > 3:  # More than 3 redirects is suspicious
            threats.append("Excessive redirect chain detected")
            evidence.append({"label": "excessive_redirects", "weight": 2, "confidence": 0.6})
            confidence_scores.append(0.6)
        elif resp.history and len(resp.history) > 1:
            threats.append("Redirect chain detected (info)")

        # (F) Enhanced rule-based NLP on HTML (skip on allowlisted hosts)
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if host.lower() not in ALLOWLIST and "text/html" in ctype:
            rb_alerts = _nlp_rule_checks(resp.text)
            threats.extend(rb_alerts)
            if rb_alerts:
                # Weight based on severity of alerts
                high_risk_alerts = [alert for alert in rb_alerts if "high-risk" in alert.lower() or "scam" in alert.lower()]
                weight = 4 if high_risk_alerts else 3
                confidence = 0.8 if high_risk_alerts else 0.6
                evidence.append({"label": "rule_based_content", "weight": weight, "confidence": confidence})
                confidence_scores.append(confidence)

    # (G) Optional ML: URL structured model
    try:
        if _url_clf and _url_feat_order:
            feats = _extract_features_from_url(url)
            row = [[feats.get(col, 0) for col in _url_feat_order]]
            pred = int(_url_clf.predict(row)[0])
            if pred == 1:
                threats.append("ML: Phishing (URL model)")
                evidence.append({"label": "ml_url_model", "weight": 4, "confidence": 0.8})
                confidence_scores.append(0.8)
    except Exception:
        # if anything goes wrong, ignore ML and keep rule-based results
        pass

    # (H) Optional ML: HTML content model (TF-IDF + classifier)
    try:
        if resp and _html_vect and _html_clf and "text/html" in (resp.headers.get("Content-Type") or "").lower():
            X = _html_vect.transform([resp.text])
            pred_html = int(_html_clf.predict(X)[0])
            if pred_html == 1:
                threats.append("ML: Malicious content (HTML model)")
                evidence.append({"label": "ml_html_model", "weight": 4, "confidence": 0.8})
                confidence_scores.append(0.8)
    except Exception:
        pass

    # Enhanced threat classification and scoring
    threats = sorted(set(threats))
    non_info_threats = [t for t in threats if not t.startswith("Unreachable or blocked") and "(info)" not in t]
    
    # Calculate overall confidence and risk score
    base_score = sum(item.get("weight", 0) for item in evidence)
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
    risk_score = base_score * avg_confidence
    
    # Determine safety based on multiple factors
    safe = (len(non_info_threats) == 0) and (risk_score < 3)
    
    # Enhanced threat level classification
    if risk_score >= 8:
        threat_level = "CRITICAL"
        emoji = "🚨"
    elif risk_score >= 5:
        threat_level = "HIGH"
        emoji = "⚠️"
    elif risk_score >= 3:
        threat_level = "MEDIUM"
        emoji = "⚡"
    elif risk_score >= 1:
        threat_level = "LOW"
        emoji = "ℹ️"
    else:
        threat_level = "SAFE"
        emoji = "✅"
    
    message = f"{emoji} {threat_level}: {', '.join(non_info_threats or threats)}" if not safe else f"{emoji} Safe browsing!"
    threat_label = "safe" if safe else f"{threat_level.lower()}_risk"

    return {
        "url": url,
        "hostname": host,
        "safe": safe,
        "threats": threats,
        "message": message,
        "threat_label": threat_label,
        "threat_level": threat_level,
        "risk_score": round(risk_score, 2),
        "confidence": round(avg_confidence, 2),
        "score": base_score,
        "evidence": evidence
    }

