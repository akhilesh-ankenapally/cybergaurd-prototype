"""
CyberGuard – Real-Time Message Simulator
==========================================
Simulates a live stream of incoming messages on WhatsApp, Instagram,
Telegram, SMS and Email. Each message is sent to the CyberGuard API
for AI-powered classification and the result is logged to the console
and stored in the threat stream (accessible via GET /stream/latest).

Run AFTER starting api_server.py:

    Terminal 1:  cd backend && python api_server.py
    Terminal 2:  cd real_time_stream && python simulator.py
"""

import time
import random
import requests
import json
import sys
from datetime import datetime

API_BASE  = "http://localhost:8000"
MIN_SLEEP = 4   # Seconds between messages (min)
MAX_SLEEP = 9   # Seconds between messages (max)

# ===== Curated sample message pool =====
# (platform, message) — realistic mix of threats and safe messages
MESSAGES = [

    # --- WhatsApp Threats ---
    ("WhatsApp", "🎉 Congratulations! You won ₹50,000 in KBC! Claim now: bit.ly/kbc-fake-2026"),
    ("WhatsApp", "Your bank OTP is 847293. Forward this to confirm your account immediately."),
    ("WhatsApp", "Work from home, earn ₹5000/day. No experience needed. Join fee ₹500 only."),
    ("WhatsApp", "URGENT: Your WhatsApp will be suspended in 24 hrs. Verify here to keep it active."),
    ("WhatsApp", "Dear user, your account has a pending reward of ₹1500. Tap to redeem now!"),

    # --- Instagram Threats ---
    ("Instagram", "🎁 You've been selected for Nike's anniversary giveaway! Click to claim: bit.ly/nike-fake"),
    ("Instagram", "Hey lovely! I'm a model in Dubai. Let's connect — I have an amazing business deal for you."),
    ("Instagram", "Your Instagram account was accessed from New York. Secure it NOW: ig-verify.net"),
    ("Instagram", "⚡ Earn $500 daily just by liking posts! Join our team. DM to start immediately!"),

    # --- Telegram Threats ---
    ("Telegram", "📈 Invest ₹10,000 today, earn ₹40,000 in 7 days! 400% guaranteed returns. Limited slots!"),
    ("Telegram", "Your Paytm account requires KYC verification. Send Aadhaar and selfie here urgently."),
    ("Telegram", "Install this APK for free premium access: t.me/free-netflix-cracked.apk"),
    ("Telegram", "CRYPTO SIGNAL ALERT: Buy BTC NOW. Our algorithm guarantees 300% profit in 48 hours."),

    # --- SMS Threats ---
    ("SMS", "FreeMsg: Your package delivery failed. Reschedule: parcel-reschedule-uk.com T&Cs apply"),
    ("SMS", "URGENT: Your SIM card will be blocked in 24hrs. Call 09XXXXXXXX to prevent deactivation."),
    ("SMS", "Congratulations! You've won a £1000 Tesco voucher. Claim at: tesco-winner.net/claim"),
    ("SMS", "Your bank account has been suspended due to suspicious activity. Verify: secure-bank-login.cc"),

    # --- Email Threats ---
    ("Email", "Dear Customer, Your account requires immediate verification. Login: my-bank-login.net"),
    ("Email", "Hi, I need you to urgently wire ₹2,50,000 to the below account. Keep this confidential."),
    ("Email", "IMPORTANT: Your Netflix subscription has expired. Update payment: netflix-update-billing.net"),
    ("Email", "Your password was changed. If this was not you, click here immediately to secure your account."),

    # --- Safe Messages ---
    ("WhatsApp", "Hey! Are you coming to the party tonight? Let me know by 7pm."),
    ("WhatsApp", "Can you bring some snacks? I'll get the drinks."),
    ("SMS",      "Your appointment is confirmed for tomorrow at 2:30 PM. Dr Sharma, Room 4."),
    ("SMS",      "Hi, your order #12345 has been dispatched. Expected delivery: Friday."),
    ("Email",    "Team meeting rescheduled to 3pm Friday. Please update your calendars."),
    ("Email",    "Please review the Q4 report attached. Let me know if you have any comments."),
    ("Instagram", "Loved your last post! The photography was absolutely stunning."),
    ("Telegram", "The deployment is complete. All services are running normally."),
    ("WhatsApp", "Mom's birthday is on Sunday. Should we get a cake from that bakery on MG Road?"),
    ("SMS",      "Your electricity bill of ₹1,248 for February has been paid successfully."),
]

LEVEL_SYMBOLS = {
    "Threat":     "🔴",
    "Suspicious": "🟡",
    "Safe":       "🟢",
}


def check_api():
    """Verify the API is reachable before starting the loop."""
    try:
        resp = requests.get(f"{API_BASE}/health", timeout=5)
        data = resp.json()
        model_status = "✅ ML Model Active" if data.get("model_loaded") else "⚠️  Keyword Fallback"
        print(f"  API Status  : {data.get('status', 'unknown').upper()}")
        print(f"  Model       : {model_status}")
        print(f"  Threat Log  : {data.get('threat_log', 0)} items")
        return True
    except requests.exceptions.ConnectionError:
        print("  ❌ Cannot reach API at", API_BASE)
        print("  Make sure api_server.py is running first.")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False


def send_message(platform: str, message: str) -> dict | None:
    """Send a message to the API for analysis and store in stream."""
    try:
        resp = requests.post(
            f"{API_BASE}/stream/add",
            json={"message": message, "platform": platform},
            timeout=5,
        )
        return resp.json()
    except Exception as e:
        print(f"  [ERROR] API call failed: {e}")
        return None


def simulate():
    print("\n" + "=" * 65)
    print("  CyberGuard – Real-Time Message Simulator")
    print("=" * 65)
    print(f"  Checking API at {API_BASE} ...")
    print("-" * 65)

    if not check_api():
        sys.exit(1)

    print("-" * 65)
    print(f"  Simulating incoming messages every {MIN_SLEEP}–{MAX_SLEEP}s")
    print(f"  Press Ctrl+C to stop\n")

    total = 0
    threats = 0
    suspicious = 0

    try:
        while True:
            platform, message = random.choice(MESSAGES)
            result = send_message(platform, message)

            if result:
                total += 1
                level   = result.get("risk_level", "Unknown")
                conf    = result.get("confidence", 0)
                symbol  = LEVEL_SYMBOLS.get(level, "⚪")
                ts      = datetime.now().strftime("%H:%M:%S")

                if level == "Threat":     threats += 1
                if level == "Suspicious": suspicious += 1

                print(
                    f"  [{ts}] {symbol} {level:<11} "
                    f"conf={conf:.0%}  |  {platform:<11}  |  "
                    f"{message[:55]}{'...' if len(message) > 55 else ''}"
                )
                print(
                    f"           Stats: {total} analyzed | "
                    f"🔴{threats} threats | 🟡{suspicious} suspicious"
                )

            sleep = random.uniform(MIN_SLEEP, MAX_SLEEP)
            time.sleep(sleep)

    except KeyboardInterrupt:
        print(f"\n\n  Simulator stopped. Summary:")
        print(f"    Total analyzed : {total}")
        print(f"    Threats        : {threats}")
        print(f"    Suspicious     : {suspicious}")
        print(f"    Safe           : {total - threats - suspicious}")
        print()


if __name__ == "__main__":
    simulate()
