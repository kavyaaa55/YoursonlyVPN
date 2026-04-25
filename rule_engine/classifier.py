# rule_engine/classifier.py
from .layer1_url      import check_url
from .layer2_metadata import check_metadata
from .layer3_content  import check_content
from .layer4_message  import check_message
from typing import Optional, Dict

LEVEL_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

def higher(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None: return b
    if b is None: return a
    return b if LEVEL_ORDER.index(b) > LEVEL_ORDER.index(a) else a

def classify(
    url:       Optional[str] = None,
    method:    str = 'GET',
    path:      str = '/',
    headers:   Dict[str, str] = {},
    body:      Optional[str] = None,
    message:   Optional[str] = None,
    is_msg:    bool = False
) -> Dict:
    """
    Master classify function.
    Returns: { 'level': 'HIGH', 'reason': 'Layer 1: URL match', 'layers_checked': 2 }
    """
    result = None
    layers_checked = 0

    # Layer 1 — URL
    if url:
        layers_checked += 1
        l1 = check_url(url)
        result = higher(result, l1)
        if result == 'CRITICAL':
            return _build(result, 'Layer 1: URL domain match', layers_checked)

    # Layer 2 — Metadata
    layers_checked += 1
    l2 = check_metadata(method, path, headers)
    result = higher(result, l2)
    if result == 'CRITICAL':
        return _build(result, 'Layer 2: Metadata match', layers_checked)

    # Layer 3 — Content (only if body present)
    if body:
        layers_checked += 1
        l3 = check_content(body)
        result = higher(result, l3)
        if result == 'CRITICAL':
            return _build(result, 'Layer 3: PII detected in body', layers_checked)

    # Layer 4 — Message (only for chat/messaging apps)
    if is_msg and message:
        layers_checked += 1
        l4 = check_message(message)
        result = higher(result, l4)

    final = result or 'LOW'
    return _build(final, 'All layers checked', layers_checked)

def _build(level, reason, layers):
    return { 'level': level, 'reason': reason, 'layers_checked': layers }
