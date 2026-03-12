"""
CyberGuard – Model Training Pipeline
=====================================
Downloads the SMS Spam Collection dataset from UCI ML Repository,
trains a Logistic Regression classifier with TF-IDF features, and
saves the trained model and vectorizer for use by the API server.

Usage:
    python model_training.py

Output:
    backend/saved_model/model.pkl
    backend/saved_model/vectorizer.pkl
"""

import os
import re
import csv
import zipfile
import urllib.request
import warnings
warnings.filterwarnings("ignore")

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# ===== Paths =====
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR   = os.path.join(BASE_DIR, "saved_model")

# ===== Dataset Source =====
# Primary: UCI ML Repository (no authentication required)
DATASET_URL  = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
DATASET_FILE = "SMSSpamCollection"

# Additional phishing/cybercrime seed phrases to augment training:
AUGMENTED_SPAM = [
    "Congratulations you won a prize. Claim now at bit.ly/win",
    "Your OTP is 847291. Forward this to confirm your account.",
    "Invest Rs 10000 get Rs 40000 guaranteed in 7 days crypto",
    "Urgent: Your account is suspended. Verify: secure-bank-login.com",
    "Free iPhone winner! Click here to claim your gift within 24 hours",
    "WINNER! You've been selected to receive a $1,000 Walmart gift card",
    "Congratulations ur awarded 500 CD vouchers or 125gift guaranteed",
    "Your SIM card will be blocked in 24hrs. Call 09XXXXXXXX to prevent",
    "KYC expiry alert: Send Aadhaar selfie on Telegram to avoid block",
    "Work from home earn 5000 per day. Registration fee Rs 500 only.",
    "Your package delivery failed. Re-confirm: parcel-track-reschd.com",
    "CEO asking you to transfer 250000 urgently. Keep confidential.",
    "IMPORTANT: Your Netflix account expires. Update billing now",
    "You've won KBC lottery. Call now to claim prize money today",
    "Free Recharge! Claim 100 RS talktime. Click link to verify number",
]

AUGMENTED_HAM = [
    "Hey, are you coming to dinner tonight?",
    "Meeting rescheduled to 3pm. See you there!",
    "Your package has been dispatched. Expected delivery Thursday.",
    "Reminder: Doctor appointment tomorrow at 10:30 AM",
    "Can you pick up some groceries on the way home?",
    "The project deadline has been extended to next Friday.",
    "Thanks for the birthday wishes! Had a great time.",
    "Don't forget we have a team lunch today at 1pm",
    "Please review the attached report when you get a chance.",
    "Call me when you are near the office, I am waiting.",
]


def download_dataset() -> str:
    """Download and extract the SMS Spam Collection dataset."""
    os.makedirs(DATASET_DIR, exist_ok=True)
    csv_path = os.path.join(DATASET_DIR, DATASET_FILE)

    if os.path.exists(csv_path):
        print(f"[INFO] Dataset already exists at: {csv_path}")
        return csv_path

    zip_path = os.path.join(DATASET_DIR, "sms_spam.zip")
    print(f"[INFO] Downloading SMS Spam Collection dataset from UCI ML Repository...")
    print(f"       Source: {DATASET_URL}")

    try:
        urllib.request.urlretrieve(DATASET_URL, zip_path)
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(DATASET_DIR)
        os.remove(zip_path)
        print(f"[OK]   Dataset extracted to: {DATASET_DIR}")
    except Exception as e:
        raise RuntimeError(
            f"Failed to download dataset: {e}\n"
            "Please manually download from:\n"
            "  https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset\n"
            f"and place 'SMSSpamCollection' in: {DATASET_DIR}"
        )

    return csv_path


def load_dataset(path: str):
    """Load the tab-separated SMS Spam Collection file."""
    labels, messages = [], []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if len(row) >= 2:
                label, msg = row[0].strip(), row[1].strip()
                if label in ("ham", "spam"):
                    labels.append(label)
                    messages.append(msg)

    print(f"[INFO] Loaded {len(messages)} messages  "
          f"({labels.count('spam')} spam / {labels.count('ham')} ham)")
    return messages, labels


def augment_data(messages, labels):
    """Add extra cybercrime-specific examples to improve detection."""
    messages = list(messages) + AUGMENTED_SPAM + AUGMENTED_HAM
    labels   = list(labels)   + ["spam"] * len(AUGMENTED_SPAM) + ["ham"] * len(AUGMENTED_HAM)
    print(f"[INFO] After augmentation: {len(messages)} total examples")
    return messages, labels


_URL_RE  = re.compile(r"https?://\S+|www\.\S+|bit\.ly\S*|tinyurl\S*")
_NUM_RE  = re.compile(r"\d+")
_PUNC_RE = re.compile(r"[^a-z\s]")
_WS_RE   = re.compile(r"\s+")

def clean_text(text: str) -> str:
    text = text.lower()
    text = _URL_RE.sub(" urltoken ", text)     # mark URLs
    text = _NUM_RE.sub(" numtoken ", text)     # mark numbers
    text = _PUNC_RE.sub(" ", text)             # remove punctuation
    text = _WS_RE.sub(" ", text).strip()
    return text


def train():
    print("=" * 60)
    print("  CyberGuard – AI Model Training")
    print("=" * 60)

    # 1. Download / locate dataset
    csv_path = download_dataset()

    # 2. Load
    messages, labels = load_dataset(csv_path)

    # 3. Augment
    messages, labels = augment_data(messages, labels)

    # 4. Clean
    print("[INFO] Cleaning and normalizing text...")
    cleaned = [clean_text(m) for m in messages]

    # 5. Train / test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        cleaned, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # 6. TF-IDF vectorization
    print("[INFO] Fitting TF-IDF vectorizer (unigrams + bigrams)...")
    vectorizer = TfidfVectorizer(
        max_features=6000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=1,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    # 7. Train Logistic Regression
    print("[INFO] Training Logistic Regression classifier...")
    model = LogisticRegression(max_iter=1000, C=5.0, solver="lbfgs", random_state=42)
    model.fit(X_train_vec, y_train)

    # 8. Evaluate
    y_pred = model.predict(X_test_vec)
    acc    = accuracy_score(y_test, y_pred)

    print(f"\n{'=' * 60}")
    print(f"  Test Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print(f"{'=' * 60}")
    print(classification_report(y_test, y_pred, target_names=["Ham (Safe)", "Spam (Threat)"]))

    # 9. Cross-validation score
    all_vec = vectorizer.transform(cleaned)
    cv_scores = cross_val_score(model, all_vec, labels, cv=5, scoring="f1_macro")
    print(f"  5-Fold Cross-Val F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # 10. Save
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, "model.pkl")
    vec_path   = os.path.join(MODEL_DIR, "vectorizer.pkl")
    joblib.dump(model,      model_path)
    joblib.dump(vectorizer, vec_path)
    print(f"\n[OK]   Model saved     → {model_path}")
    print(f"[OK]   Vectorizer saved → {vec_path}")
    print("\n  Run the API server next:")
    print("  > python api_server.py\n")


if __name__ == "__main__":
    train()
