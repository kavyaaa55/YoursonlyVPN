# encryption/cipher_selector.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
import os

PROFILES = {
    'CRITICAL': {
        'cipher':   'AES-256-GCM',
        'key_bits': 256,
        'tls':      '1.3',
        'pfs':      True,
        'cert_pin': True,
        'double':   True,    # Double-encrypt
        'proto':    'TCP',
        'latency':  'none',
    },
    'HIGH': {
        'cipher':   'AES-256-GCM',
        'key_bits': 256,
        'tls':      '1.3',
        'pfs':      True,
        'cert_pin': False,
        'double':   False,
        'proto':    'TCP',
        'latency':  '<50ms',
    },
    'MEDIUM': {
        'cipher':   'AES-128-GCM',
        'key_bits': 128,
        'tls':      '1.3',
        'pfs':      False,
        'cert_pin': False,
        'double':   False,
        'proto':    'TCP',
        'latency':  '<30ms',
    },
    'LOW': {
        'cipher':   'ChaCha20-Poly1305',
        'key_bits': 256,
        'tls':      '1.2',
        'pfs':      False,
        'cert_pin': False,
        'double':   False,
        'proto':    'UDP',
        'latency':  '<10ms',
    },
}

def encrypt_payload(level: str, plaintext: bytes) -> dict:
    """
    Encrypt payload using the cipher for the given sensitivity level.
    Returns: { 'ciphertext': bytes, 'nonce': bytes, 'profile': dict }
    """
    profile = PROFILES[level]
    key_bytes = profile['key_bits'] // 8
    key   = os.urandom(key_bytes)
    nonce = os.urandom(12)

    if profile['cipher'] == 'ChaCha20-Poly1305':
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
    else:
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

    # Double-encrypt for CRITICAL
    if profile['double']:
        key2   = os.urandom(32)
        nonce2 = os.urandom(12)
        cipher2 = AESGCM(key2)
        ciphertext = cipher2.encrypt(nonce2, ciphertext, None)

    return { 'ciphertext': ciphertext, 'nonce': nonce, 'profile': profile }
