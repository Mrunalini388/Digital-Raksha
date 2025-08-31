# utils.py
def scan_url(url):
    """
    Simple heuristic scanner using keywords.
    """
    phishing_keywords = ["login", "verify", "update", "password", "bank", "account"]

    if any(word in url.lower() for word in phishing_keywords):
        return {"threat": "phishing", "message": "🚨 Digital Raksha Alert: This site looks like a phishing attempt!"}
    
    return {"threat": "safe", "message": "✅ URL seems safe."}
