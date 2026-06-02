from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
import joblib
import json
import re
import math
import os
import ipaddress
import socket
from urllib.parse import urlparse
from collections import Counter

app = FastAPI(title="Phishing Detector API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
    model = None
    feature_columns = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slash', 'num_special_chars',
        'has_ip', 'has_at_symbol', 'has_double_slash', 'is_https', 'subdomain_depth',
        'path_length', 'num_subdomains', 'has_suspicious_word', 'entropy', 'domain_length'
    ]
    MODEL_LOADED = False

# Whitelist of trusted domains that bypass the model
WHITELISTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "whatsapp.com", "linkedin.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "netflix.com",
    "spotify.com", "paypal.com", "zoom.us", "slack.com",
    "dropbox.com", "onedrive.com", "drive.google.com", "gmail.com",
    "outlook.com", "yahoo.com", "bing.com", "duckduckgo.com",
}

# Known brands that phishers commonly impersonate
PROTECTED_BRANDS = {
    "paypal", "apple", "icloud", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "twitter",
    "linkedin", "dropbox", "spotify", "ebay", "chase", "wellsfargo",
    "bankofamerica", "citibank", "dhl", "fedex", "ups", "usps"
}

def has_brand_impersonation(url: str, root_domain: str) -> bool:
    url_lower = url.lower()
    for brand in PROTECTED_BRANDS:
        if brand in url_lower and brand not in root_domain:
            return True
    return False

class URLRequest(BaseModel):
    url: str = Field(..., max_length=2048)

def get_entropy(url):
    if not url:
        return 0.0
    counts = Counter(url)
    probs = [c / len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def get_root_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
    except:
        return ""

def is_safe_url(url: str) -> bool:
    """Block SSRF — rejects localhost, private IPs, non-HTTP schemes"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname in ('localhost', '::1'):
            return False
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return False
        except (socket.gaierror, ValueError):
            pass
        return True
    except Exception:
        return False

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
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
        "message": "Phishing Detector API is running 🚀",
        "model_loaded": MODEL_LOADED,
        "version": "2.0.6"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": MODEL_LOADED,
        "features_count": len(feature_columns)
    }

@app.post("/predict")
@limiter.limit("5/minute")
def predict(request: Request, url_request: URLRequest):
    if not is_safe_url(url_request.url):
        raise HTTPException(status_code=400, detail="URL not allowed")

    root_domain = get_root_domain(url_request.url)

    if root_domain in WHITELISTED_DOMAINS:
        return {
            "url": url_request.url,
            "prediction": "legitimate",
            "confidence": 100.0,
            "phishing_probability": 0.0,
            "note": "Domain is whitelisted as trusted"
        }

    if has_brand_impersonation(url_request.url, root_domain):
        return {
            "url": url_request.url,
            "prediction": "phishing",
            "confidence": 95.0,
            "phishing_probability": 95.0,
            "note": "Possible brand impersonation detected"
        }

    try:
        features = extract_features(url_request.url)
        if not MODEL_LOADED:
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
                "url": url_request.url,
                "prediction": "phishing" if prediction == 1 else "legitimate",
                "confidence": round(max(prob_phishing, prob_legit) * 100, 2),
                "phishing_probability": round(prob_phishing * 100, 2),
                "mode": "demo"
            }
        values = [[features[col] for col in feature_columns]]
        prediction = model.predict(values)[0]
        probability = model.predict_proba(values)[0]
        return {
            "url": url_request.url,
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2),
            "mode": "production"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))