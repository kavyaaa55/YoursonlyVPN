# rule_engine/layer1_url.py
import re
from typing import Optional

# Sensitivity level constants
CRITICAL = 'CRITICAL'
HIGH     = 'HIGH'
MEDIUM   = 'MEDIUM'
LOW      = 'LOW'

# Domain rules — longest/most-specific match wins
DOMAIN_RULES = {
    # Indian government — always CRITICAL
    'uidai.gov.in':           CRITICAL,
    'incometax.gov.in':       CRITICAL,
    'passportindia.gov.in':   CRITICAL,
    'digilocker.gov.in':      CRITICAL,
    'epfindia.gov.in':        CRITICAL,
    # Banking
    'sbi.co.in':              CRITICAL,
    'hdfcbank.com':           CRITICAL,
    'icicibank.com':          CRITICAL,
    'axisbank.com':           CRITICAL,
    'paytm.com':              HIGH,
    'phonepe.com':            HIGH,
    'gpay.app':               HIGH,
    # Gaming / Streaming — fast mode
    'steampowered.com':       LOW,
    'epicgames.com':          LOW,
    'youtube.com':            LOW,
    'netflix.com':            LOW,
    'hotstar.com':            LOW,
    'jiocinema.com':          LOW,
    'primevideo.com':         LOW,
    'twitch.tv':              LOW,
}

# Wildcard pattern rules (checked if exact match fails)
PATTERN_RULES = [
    (r'.*\.gov\.in$',       CRITICAL),
    (r'.*bank.*\.com$',      HIGH),
    (r'.*pay.*\.com$',       HIGH),
    (r'.*finance.*\.com$',   HIGH),
]

def check_url(url: str) -> Optional[str]:
    """
    Returns sensitivity level if URL matches a rule, else None.
    None means: proceed to next layer.
    """
    # Strip protocol
    domain = url.lower()
    for prefix in ['https://', 'http://', 'www.']:
        domain = domain.replace(prefix, '')
    domain = domain.split('/')[0].split(':')[0]

    # Exact match first
    if domain in DOMAIN_RULES:
        return DOMAIN_RULES[domain]

    # Subdomain match (e.g. 'login.sbi.co.in')
    for key, level in DOMAIN_RULES.items():
        if domain.endswith('.' + key):
            return level

    # Wildcard pattern match
    for pattern, level in PATTERN_RULES:
        if re.match(pattern, domain):
            return level

    return None  # No match — go to Layer 2
