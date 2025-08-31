# scanner.py
import time
from utils import scan_url
from detector import analyze_url
from nlp_helper import nlp_clf, url_text_repr, fetch_page

def scan_url_full(url: str):
    t0 = time.time()
    findings = []

    # Detector rules
    try:
        detector_result = analyze_url(url)
        for threat in detector_result.get("threats", []):
            findings.append({
                "source": "detector",
                "label": threat.replace(" ", "-").lower(),
                "score": 0.7,
                "evidence": {}
            })
    except Exception:
        pass

    # Keyword heuristics
    try:
        util_result = scan_url(url)
        if util_result["threat"] != "safe":
            findings.append({
                "source": "utils",
                "label": util_result["threat"],
                "score": 0.6,
                "evidence": {}
            })
    except Exception:
        pass

    # NLP
    phishing_score = 0.0
    phishing_label = "unknown"
    try:
        html = fetch_page(url)
        if nlp_clf:
            doc = url_text_repr(url, html)
            proba = nlp_clf.predict_proba([doc])[0]
            phishing_score = float(proba[1])
            pred = nlp_clf.predict([doc])[0]
            phishing_label = "phishing" if int(pred) == 1 else "safe"
            if int(pred) == 1:
                findings.append({
                    "source": "nlp",
                    "label": "phishing",
                    "score": phishing_score,
                    "evidence": {}
                })
        else:
            phishing_label = "model_not_loaded"
    except Exception:
        phishing_label = "error"

    risk = max((f["score"] for f in findings), default=0.0)
    if risk >= 0.8:
        decision = "block"
    elif risk >= 0.5:
        decision = "warn"
    else:
        decision = "allow"

    safe = decision == "allow"
    elapsed_ms = int((time.time() - t0) * 1000)

    return {
        "url": url,
        "safe": safe,
        "decision": decision,
        "risk": round(risk, 2),
        "findings": findings,
        "nlp": {"label": phishing_label, "phishing_score": round(phishing_score, 4)},
        "perf_ms": elapsed_ms
    }
