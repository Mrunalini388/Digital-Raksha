# nlp_helper.py
import joblib
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import requests

MODEL_PATH = "nlp_model.pkl"

# Load NLP model
try:
    nlp_clf = joblib.load(MODEL_PATH)
except Exception:
    nlp_clf = None
    print("WARNING: NLP model not loaded.")

# Fetch page HTML
REQUEST_TIMEOUT = 6
USER_AGENT = "DigitalRaksha/1.0"

def fetch_page(url: str) -> str:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        ct = resp.headers.get("Content-Type", "")
        if "text/html" in ct.lower():
            return resp.text or ""
        return ""
    except Exception:
        return ""

# Build text representation for NLP model
def url_text_repr(url: str, html: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(url)
    title = ""
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            title = (soup.title.string or "").strip() if soup.title else ""
            for tag in soup(["script", "style", "noscript"]):
                tag.extract()
            text_snippet = " ".join(soup.get_text(" ", strip=True).split())[:1200]
        except Exception:
            text_snippet = ""
    else:
        text_snippet = ""
    doc = " ".join([url, host.replace(".", " "), ext.domain or "", ext.suffix or "", title, text_snippet])
    return doc
