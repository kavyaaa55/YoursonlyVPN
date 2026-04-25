# rule_engine/layer4_message.py
import re
from typing import Optional

CRITICAL = 'CRITICAL'; HIGH = 'HIGH'; LOW = 'LOW'

CRITICAL_KEYWORDS = [
    'otp', 'one time password', 'verification code',
    'account number', 'account no', 'ifsc',
    'aadhaar', 'pan card', 'cvv', 'card number',
    'upi pin', 'mpin', 'atm pin',
]

HIGH_KEYWORDS = [
    'password', 'passphrase', 'login', 'credentials',
    'bank', 'transfer', 'salary', 'transaction',
    'upi', 'neft', 'rtgs', 'imps',
]

LOW_INDICATORS = [
    'lol', 'haha', 'meme', 'ok', 'sure', 'thanks',
    'hey', 'hi', 'hello', 'bye', 'good morning',
]

def check_message(text: str) -> str:
    """
    Always returns a level (messages always have some classification).
    Defaults to MEDIUM if no specific keyword found.
    """
    text_lower = text.lower()

    # Check CRITICAL first
    for kw in CRITICAL_KEYWORDS:
        if kw in text_lower:
            return CRITICAL

    # Check HIGH
    for kw in HIGH_KEYWORDS:
        if kw in text_lower:
            return HIGH

    # Check LOW (casual messages)
    low_count = sum(1 for kw in LOW_INDICATORS if kw in text_lower)
    if low_count >= 2:
        return LOW

    return 'MEDIUM'   # Default for unknown messages
