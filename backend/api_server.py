"""
CyberGuard – FastAPI Backend Server
=====================================
Serves the trained ML model via REST API.

Endpoints:
  GET  /health           → API + model health check
  POST /analyze          → Analyze a message for phishing/spam
  GET  /stream/latest    → Latest threats detected by the real-time simulator
  POST /stream/add       → Internal: simulator pushes threats here
  POST /stream/clear     → Clear the threat stream log

Usage:
    python api_server.py
    # or
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import re
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cyberguard")

# ===== Paths =====
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, "saved_model")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
VEC_PATH   = os.path.join(MODEL_DIR, "vectorizer.pkl")

# ===== Global State =====
_model      = None
_vectorizer = None
_threat_log: List[dict] = []   # In-memory threat stream (latest 50 items)
MAX_LOG     = 50


# ===== Text Cleaning (must match model_training.py) =====
_URL_RE  = re.compile(r"https?://\S+|www\.\S+|bit\.ly\S*|tinyurl\S*")
_NUM_RE  = re.compile(r"\d+")
_PUNC_RE = re.compile(r"[^a-z\s]")
_WS_RE   = re.compile(r"\s+")

def _clean(text: str) -> str:
    text = text.lower()
    text = _URL_RE.sub(" urltoken ", text)
    text = _NUM_RE.sub(" numtoken ", text)
    text = _PUNC_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


# ===== Keyword fallback (when model not loaded) =====
_DANGER_KEYWORDS   = ["won", "winner", "prize", "free", "urgent", "otp", "forward otp",
                       "congratulations", "claim", "bit.ly", "tinyurl", "verify account",
                       "suspended", "kyc", "lottery", "guaranteed return", "invest now",
                       "bank account blocked", "confirm your account", "password"]
_WARN_KEYWORDS     = ["click", "link", "verify", "login", "bank", "account", "limited",
                       "offer", "discount", "limited time", "expire", "reward", "selected",
                       "exclusive", "voucher", "token"]

def _keyword_predict(message: str):
    lower = message.lower()
    danger_hits = sum(1 for k in _DANGER_KEYWORDS if k in lower)
    warn_hits   = sum(1 for k in _WARN_KEYWORDS   if k in lower)
    if danger_hits >= 2 or (danger_hits >= 1 and warn_hits >= 2):
        return "Threat",     min(0.60 + danger_hits * 0.07, 0.95)
    if danger_hits == 1 or warn_hits >= 2:
        return "Suspicious", min(0.40 + warn_hits * 0.05, 0.70)
    return "Safe", max(0.90 - warn_hits * 0.05, 0.60)


def _ml_predict(message: str):
    """Run the trained ML model and map output to risk levels."""
    cleaned = _clean(message)
    vec     = _vectorizer.transform([cleaned])
    proba   = _model.predict_proba(vec)[0]

    classes    = list(_model.classes_)
    spam_prob  = proba[classes.index("spam")]
    ham_prob   = proba[classes.index("ham")]

    if spam_prob >= 0.70:
        return "Threat",     float(spam_prob)
    if spam_prob >= 0.30:
        return "Suspicious", float(spam_prob)
    return "Safe", float(ham_prob)


def predict(message: str, platform: str = "unknown"):
    use_ml = (_model is not None and _vectorizer is not None)
    if use_ml:
        risk_level, confidence = _ml_predict(message)
    else:
        risk_level, confidence = _keyword_predict(message)

    return {
        "risk_level":      risk_level,
        "confidence":      round(confidence, 4),
        "model_used":      "AI (Logistic Regression)" if use_ml else "Keyword Fallback",
        "message_preview": message[:120],
        "platform":        platform,
        "timestamp":       datetime.now().isoformat(timespec="seconds"),
    }


# ===== FastAPI Lifespan =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _model, _vectorizer
    if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
        try:
            _model      = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VEC_PATH)
            logger.info("✅ ML model loaded successfully.")
        except Exception as e:
            logger.warning(f"⚠️  Could not load model: {e}. Using keyword fallback.")
    else:
        logger.warning(
            "⚠️  No trained model found. Run 'python model_training.py' first.\n"
            "    Using keyword-based fallback for now."
        )
    yield
    logger.info("Shutting down CyberGuard API.")


# ===== App =====
app = FastAPI(
    title="CyberGuard AI API",
    description="Real-time phishing and cybercrime detection API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Allow all origins including file:// for local dev
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== Schemas =====
class AnalyzeRequest(BaseModel):
    message:  str
    platform: Optional[str] = "unknown"

class AnalyzeResponse(BaseModel):
    risk_level:      str
    confidence:      float
    model_used:      str
    message_preview: str
    platform:        str
    timestamp:       str

class StreamAddRequest(BaseModel):
    message:  str
    platform: str


# ===== Endpoints =====

@app.get("/health", tags=["Status"])
def health():
    return {
        "status":       "ok",
        "model_loaded": _model is not None,
        "model_type":   "Logistic Regression + TF-IDF" if _model else "Keyword Fallback",
        "threat_log":   len(_threat_log),
        "version":      "2.0.0",
    }


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Detection"])
def analyze(request: AnalyzeRequest):
    if not request.message or not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    result = predict(request.message.strip(), request.platform or "unknown")

    # Auto-log threats to the stream
    if result["risk_level"] in ("Threat", "Suspicious"):
        _threat_log.insert(0, result)
        if len(_threat_log) > MAX_LOG:
            _threat_log.pop()

    return result


@app.post("/stream/add", tags=["Stream"])
def stream_add(request: StreamAddRequest):
    """Used by the real-time simulator to push messages into the detection pipeline."""
    result = predict(request.message, request.platform)
    _threat_log.insert(0, result)
    if len(_threat_log) > MAX_LOG:
        _threat_log.pop()
    return result


@app.get("/stream/latest", tags=["Stream"])
def stream_latest(limit: int = 10):
    """Returns the most recent threats detected by the real-time stream."""
    return {
        "count":   min(limit, len(_threat_log)),
        "threats": _threat_log[:limit],
    }


@app.post("/stream/clear", tags=["Stream"])
def stream_clear():
    _threat_log.clear()
    return {"status": "cleared", "count": 0}


@app.get("/", tags=["Status"])
def root():
    return {
        "name":    "CyberGuard AI API",
        "version": "2.0.0",
        "docs":    "/docs",
        "health":  "/health",
    }


if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("  CyberGuard AI Backend Server")
    print("=" * 60)
    print(f"  API running at: http://localhost:8000")
    print(f"  Docs:           http://localhost:8000/docs")
    print(f"  Health:         http://localhost:8000/health")
    print("=" * 60 + "\n")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)
