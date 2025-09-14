# scanner.py
from nlp_helper import nlp_clf, fetch_page
from utils import scan_url as simple_scan

def scan_url_full(url):
    """
    Scan a URL using NLP model if available; otherwise fall back to simple heuristics.
    Returns: { safe: bool, decision: str, message: str }
    """
    # Fallback to heuristics when model is missing
    if nlp_clf is None:
        basic = simple_scan(url)
        return {
            "safe": basic.get("threat") == "safe",
            "decision": basic.get("threat"),
            "message": basic.get("message", "Scanned with heuristics.")
        }

    try:
        html = fetch_page(url)
        text_input = html if html else url
        pred = int(nlp_clf.predict([text_input])[0])
        is_safe = (pred == 0)
        decision = "safe" if is_safe else "malicious"
        return {
            "safe": is_safe,
            "decision": decision,
            "message": "URL scanned successfully using NLP."
        }
    except Exception as e:
        print(f"NLP scan error for {url}: {e}")
        basic = simple_scan(url)
        return {
            "safe": basic.get("threat") == "safe",
            "decision": basic.get("threat"),
            "message": f"NLP failed, heuristics used: {basic.get('message', 'unknown')}"
        }

