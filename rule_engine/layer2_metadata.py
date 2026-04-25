# rule_engine/layer2_metadata.py
from typing import Optional, Dict

CRITICAL = 'CRITICAL'; HIGH = 'HIGH'; MEDIUM = 'MEDIUM'; LOW = 'LOW'

# Path keyword rules
PATH_RULES = [
    ('/payment',    CRITICAL),
    ('/checkout',   CRITICAL),
    ('/transfer',   CRITICAL),
    ('/api/otp',    CRITICAL),
    ('/login',      HIGH),
    ('/signin',     HIGH),
    ('/auth',       HIGH),
    ('/api/user',   HIGH),
    ('/upload',     MEDIUM),
    ('/api/',       MEDIUM),
]

# Content-Type rules
CONTENT_TYPE_RULES = {
    'multipart/form-data':    MEDIUM,   # File upload
    'application/json':       MEDIUM,   # API call
    'video/':                 LOW,       # Streaming
    'audio/':                 LOW,
    'image/':                 LOW,
}

def check_metadata(method: str, path: str, headers: Dict[str, str]) -> Optional[str]:
    """Returns sensitivity label or None to continue to Layer 3."""
    highest = None

    # POST/PUT always more sensitive than GET
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        highest = MEDIUM

    # Path matching
    path_lower = path.lower()
    for keyword, level in PATH_RULES:
        if keyword in path_lower:
            highest = _higher(highest, level)
            break

    # Content-Type matching
    ct = headers.get('content-type', '').lower()
    for ct_key, level in CONTENT_TYPE_RULES.items():
        if ct.startswith(ct_key):
            highest = _higher(highest, level)
            break

    return highest

LEVEL_ORDER = [LOW, MEDIUM, HIGH, CRITICAL]

def _higher(a: Optional[str], b: str) -> str:
    if a is None: return b
    return b if LEVEL_ORDER.index(b) > LEVEL_ORDER.index(a) else a
