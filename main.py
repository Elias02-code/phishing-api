from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import json
import re
import math
from urllib.parse import urlparse
from collections import Counter

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Enable CORS - allows the HTML UI to connect from any origin/website
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model and feature columns
try:
    model = joblib.load("model/phishing_detector.pkl")
    with open("model/feature_columns.json") as f:
        feature_columns = json.load(f)
    MODEL_LOADED = True
except Exception as e:
    print(f"Warning: Could not load model - {e}")
    print("Running in DEMO mode with mock predictions")
    model = None
    feature_columns = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slash', 'num_special_chars',
        'has_ip', 'has_at_symbol', 'has_double_slash', 'is_https', 'subdomain_depth',
        'path_length', 'num_subdomains', 'has_suspicious_word', 'entropy', 'domain_length'
    ]
    MODEL_LOADED = False

# Your API key - share this with your Android team
API_KEY = "The-01guardian-AI-0205-secured-key"
# Whitelist of trusted domains that bypass the model, (this is a simple heuristic to improve performance and reduce false positives for well-known sites)
WHITELISTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "whatsapp.com", "linkedin.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "netflix.com",
    "spotify.com", "paypal.com", "zoom.us", "slack.com",
    "dropbox.com", "onedrive.com", "drive.google.com", "gmail.com",
    "outlook.com", "yahoo.com", "bing.com", "duckduckgo.com",
}

# Request schema
class URLRequest(BaseModel):
    url: str

# Feature extractor
def get_entropy(url):
    if not url:
        return 0.0
    counts = Counter(url)
    probs = [c / len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def get_root_domain(url: str) -> str:
    """Extract root domain from URL e.g. mail.google.com → google.com"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]
        # Extract last two parts e.g. mail.google.com → google.com
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
    except:
        return ""
    
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # Handle URLs without scheme
    if not domain and path:
        parts = path.split('/')
        domain = parts[0]
        path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else ''

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
        'num_subdomains': domain.count('.') if domain else 0,
        'has_suspicious_word': 1 if re.search(
            r'login|verify|secure|account|update|banking|confirm|password|signin|webscr',
            url, re.IGNORECASE) else 0,
        'entropy': get_entropy(url),
        'domain_length': len(domain),
    }

@app.get("/")
def root():
    return {
        "message": "Phishing Detector API is running",
        "model_loaded": MODEL_LOADED,
        "version": "2.0.4"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": MODEL_LOADED,
        "features_count": len(feature_columns)
    }

@app.post("/predict")
def predict(request: URLRequest, x_api_key: str = Header(None)):
    # Check API key
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# Check the whitelist domain before running phishing model
    root_domain = get_root_domain(request.url)
    if root_domain in WHITELISTED_DOMAINS:
        return {
            "url": request.url,
            "prediction": "legitimate",
            "confidence": 100.0,
            "phishing_probability": 0.0,
            "note": "Domain is whitelisted as trusted"
        }
    
    # Check for brand impersonation - if the URL contains a well-known brand name but is not the official domain,
    # flag it as phishing 
    # (this is a simple heuristic to catch common impersonation attempts)
if has_brand_impersonation(request.url, root_domain):
    return {
        "url": request.url,
        "prediction": "phishing",
        "confidence": 95.0,
        "phishing_probability": 95.0,
        "note": "Possible brand impersonation detected"
    }

    try:
        features = extract_features(request.url)

        # If model is not loaded, use heuristic-based demo prediction
        if not MODEL_LOADED:
            # Simple heuristic for demo mode
            score = 0
            if features['has_ip']: score += 30
            if features['has_at_symbol']: score += 25
            if features['has_suspicious_word']: score += 20
            if features['num_dots'] > 3: score += 10
            if features['subdomain_depth'] > 1: score += 10
            if features['entropy'] > 4.5: score += 5

            prediction = 1 if score > 40 else 0
            prob_phishing = min(score / 100, 0.99)
            prob_legit = 1 - prob_phishing

            return {
                "url": request.url,
                "prediction": "phishing" if prediction == 1 else "legitimate",
                "confidence": round(max(prob_phishing, prob_legit) * 100, 2),
                "phishing_probability": round(prob_phishing * 100, 2),
                "mode": "demo",
                "features": features
            }

        values = [[features[col] for col in feature_columns]]
        prediction = model.predict(values)[0]
        probability = model.predict_proba(values)[0]

        return {
            "url": request.url,
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2),
            "mode": "production",
            "features": features
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
