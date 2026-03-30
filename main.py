from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import joblib
import json
import re
import math
from urllib.parse import urlparse
from collections import Counter

app = FastAPI(title="Phishing Detector API")

# Load model and feature columns
model = joblib.load("model/phishing_detector.pkl")
with open("model/feature_columns.json") as f:
    feature_columns = json.load(f)

# Your API key - share this with your Android team
API_KEY = "guardian-ai-2026-secure-key"

# Request schema
class URLRequest(BaseModel):
    url: str

# Feature extractor
def get_entropy(url):
    counts = Counter(url)
    probs = [c / len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    return {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slash': url.count('/'),
        'num_special_chars': len(re.findall(r'[@_!#$%^&*()<>?/|}{~:]', url)),
        'has_ip': 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0,
        'has_at_symbol': 1 if '@' in url else 0,
        'has_double_slash': 1 if '//' in path else 0,
        'is_https': 1 if parsed.scheme == 'https' else 0,
        'subdomain_depth': len(domain.split('.')) - 2 if domain else 0,
        'path_length': len(path),
        'num_subdomains': domain.count('.'),
        'has_suspicious_word': 1 if re.search(
            r'login|verify|secure|account|update|banking|confirm|password|signin|webscr',
            url, re.IGNORECASE) else 0,
        'entropy': get_entropy(url),
        'domain_length': len(domain),
    }

@app.get("/")
def root():
    return {"message": "Phishing Detector API is running 🚀"}

@app.post("/predict")
def predict(request: URLRequest, x_api_key: str = Header(None)):
    # Check API key
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    
    try:
        features = extract_features(request.url)
        values = [[features[col] for col in feature_columns]]
        prediction = model.predict(values)[0]
        probability = model.predict_proba(values)[0]

        return {
            "url": request.url,
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2)
        }
    except Exception as e:
        return {"error": str(e)}