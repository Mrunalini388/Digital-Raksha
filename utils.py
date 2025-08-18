import re

def scan_url(url):
    """
    Simple threat detection placeholder.
    Replace with ML/NLP logic later.
    """
    phishing_keywords = ["login", "verify", "update", "password", "bank", "account"]

    if any(word in url.lower() for word in phishing_keywords):
        threat = "phishing"
        message = "🚨 Digital Raksha Alert: This site looks like a phishing attempt!"
    else:
        threat = "safe"
        message = "✅ URL seems safe."
    
    return threat, message
