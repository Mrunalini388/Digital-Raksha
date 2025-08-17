import os, csv, joblib, random
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = "nlp_model.pkl"
DATA_CSV = "nlp_training_data.csv"  # optional, if present use it

def make_fallback_data():
    # minimal synthetic samples
    phishing_samples = [
        "login verify account urgent action required password reset banking",
        "win prize click link confirm credentials",
        "update payment info now otherwise account suspended",
        "security alert unusual activity verify identity",
        "free gift card limited time click here"
    ]
    safe_samples = [
        "welcome to university library resources",
        "official documentation python tutorial reference",
        "news article technology updates review",
        "local government services information",
        "open source project github readme installation"
    ]
    X = phishing_samples + safe_samples
    y = [1]*len(phishing_samples) + [0]*len(safe_samples)
    pack = list(zip(X, y))
    random.shuffle(pack)
    X, y = zip(*pack)
    return list(X), list(y)

def load_csv_if_any(path):
    rows = []
    if Path(path).exists():
        with open(path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    rows.append((row["text"], int(row["label"])))
                except Exception:
                    pass
    return rows

def main():
    rows = load_csv_if_any(DATA_CSV)
    if rows:
        X, y = zip(*rows)
        X, y = list(X), list(y)
        print(f"Loaded {len(X)} rows from {DATA_CSV}")
    else:
        X, y = make_fallback_data()
        print(f"Using fallback synthetic dataset: {len(X)} samples")

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1,2),
            min_df=1,
            max_features=12000,
            lowercase=True,
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(
            max_iter=600,
            n_jobs=None,
        )),
    ])
    pipe.fit(X, y)
    joblib.dump(pipe, MODEL_PATH)
    print("Saved model ->", MODEL_PATH)

if __name__ == "__main__":
    main()
