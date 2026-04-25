# rule_engine/layer3_content.py
import re
from typing import Optional

CRITICAL = 'CRITICAL'; HIGH = 'HIGH'; MEDIUM = 'MEDIUM'
LEVEL_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

# Pre-compiled regex patterns for performance
CONTENT_PATTERNS = [
    # ── Indian PII — CRITICAL ─────────────────────────────
    (re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b'),          CRITICAL, 'Aadhaar'),
    (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),             CRITICAL, 'PAN Card'),
    (re.compile(r'\b\d{10}\b'),                            CRITICAL, 'Passport/Account No'),
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),           CRITICAL, 'Visa Card'),
    (re.compile(r'\b5[1-5][0-9]{14}\b'),                   CRITICAL, 'Mastercard'),
    (re.compile(r'\b3[47][0-9]{13}\b'),                    CRITICAL, 'Amex Card'),
    (re.compile(r'\b\d{9,18}\b'),                         CRITICAL, 'Bank Acct No'),
    # ── Indian UPI / Payment — HIGH ───────────────────────
    (re.compile(r'[\w.]+@(paytm|oksbi|okaxis|ybl|okhdfcbank|ibl)'), HIGH, 'UPI ID'),
    (re.compile(r'\+91[\-\s]?[6-9]\d{9}\b'),           HIGH, 'Indian Phone'),
    (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),             HIGH, 'IFSC Code'),
    # ── Sensitive Keywords — HIGH ─────────────────────────
    (re.compile(r'\b(cvv|otp|pin|password|passwd|secret|token)\b', re.I), HIGH, 'Credential'),
    (re.compile(r'\b(aadhaar|aadhar|pan.card|passport.no)\b', re.I),     HIGH, 'PII Keyword'),
    # ── Medical — HIGH ────────────────────────────────────
    (re.compile(r'\b(diagnosis|prescription|blood.group|medical.record)\b', re.I), HIGH, 'Medical'),
    # ── Email — MEDIUM ────────────────────────────────────
    (re.compile(r'[\w.\-]+@[\w.\-]+\.[a-z]{2,}'),      MEDIUM, 'Email'),
]

def check_content(body: str) -> Optional[str]:
    """
    Scans request body on-device.
    Returns highest sensitivity label found, or None.
    """
    if not body or len(body) > 500_000:   # Skip huge payloads (videos etc.)
        return None

    highest = None
    for pattern, level, name in CONTENT_PATTERNS:
        if pattern.search(body):
            if highest is None or LEVEL_ORDER.index(level) > LEVEL_ORDER.index(highest):
                highest = level
            if highest == CRITICAL:
                break   # Can't go higher, stop early

    return highest
