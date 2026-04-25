# tunnel/vpn_tunnel.py
"""
Real VPN packet encapsulation + Adaptive Controller.

VPN Frame layout (binary):
  [4B  magic ] [1B version] [1B  flags ] [2B  frame_len]
  [16B session_id         ] [4B  seq_no ]
  [1B  sensitivity_label  ] [12B nonce  ]
  [2B  cipher_id          ] [2B  mtu    ]
  [8B  timestamp_ms       ]
  [N B ciphertext         ]
  [16B auth_tag (GCM)     ]  ← already appended by AESGCM/ChaCha20

Flags byte:
  bit 0 = double_encrypted
  bit 1 = pfs_enabled
  bit 2 = tcp_mode  (0 = UDP)
  bit 3 = cert_pinned
"""

import os, struct, time, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ── Constants ────────────────────────────────────────────────────────────────
MAGIC   = b'\xAD\xAD\x56\x50'   # 0xADAD5650 — "ADAPTVPN" marker
VERSION = 1

CIPHER_ID = {
    'AES-256-GCM':       0x01,
    'AES-128-GCM':       0x02,
    'ChaCha20-Poly1305': 0x03,
}
CIPHER_ID_REV = {v: k for k, v in CIPHER_ID.items()}

LABEL_ID = {'CRITICAL': 0x04, 'HIGH': 0x03, 'MEDIUM': 0x02, 'LOW': 0x01}

# MTU per sensitivity (bytes) — lower sensitivity = larger MTU (less overhead)
MTU_MAP = {'CRITICAL': 512, 'HIGH': 1024, 'MEDIUM': 1280, 'LOW': 1500}

# ── Session store (in-memory, keyed by session_id hex) ───────────────────────
_sessions: dict = {}

# ── Adaptive Controller ───────────────────────────────────────────────────────
class AdaptiveController:
    """
    Tracks per-session RTT history and adjusts cipher/MTU/protocol
    dynamically based on both sensitivity level AND network conditions.
    """
    def __init__(self):
        self.rtt_window: list[float] = []   # last 10 RTTs in ms
        self.drop_count: int = 0
        self.total_packets: int = 0

    def record_rtt(self, rtt_ms: float):
        self.rtt_window.append(rtt_ms)
        if len(self.rtt_window) > 10:
            self.rtt_window.pop(0)
        self.total_packets += 1

    @property
    def avg_rtt(self) -> float:
        return sum(self.rtt_window) / len(self.rtt_window) if self.rtt_window else 0.0

    @property
    def jitter(self) -> float:
        if len(self.rtt_window) < 2:
            return 0.0
        diffs = [abs(self.rtt_window[i] - self.rtt_window[i-1]) for i in range(1, len(self.rtt_window))]
        return sum(diffs) / len(diffs)

    def adapt(self, base_level: str) -> dict:
        """
        Returns adapted profile. May downgrade cipher under high RTT,
        or upgrade protocol under low jitter.
        """
        avg  = self.avg_rtt
        jit  = self.jitter

        # Start from the base sensitivity profile
        level  = base_level
        reason = 'nominal'

        # Under very high RTT (>300ms) and LOW/MEDIUM sensitivity → stay but note it
        if avg > 300 and level in ('LOW', 'MEDIUM'):
            reason = f'high-RTT({avg:.0f}ms): keeping {level} profile'

        # Under high jitter (>80ms) → force TCP even for LOW
        force_tcp = jit > 80
        if force_tcp and level == 'LOW':
            reason = f'high-jitter({jit:.0f}ms): forcing TCP'

        # MTU shrinks under high jitter to reduce retransmits
        mtu = MTU_MAP[level]
        if jit > 50:
            mtu = max(512, mtu - 256)

        return {
            'adapted_level':  level,
            'force_tcp':      force_tcp,
            'mtu':            mtu,
            'avg_rtt_ms':     round(avg, 1),
            'jitter_ms':      round(jit, 1),
            'adapt_reason':   reason,
            'total_packets':  self.total_packets,
        }

# ── Session ───────────────────────────────────────────────────────────────────
class VPNSession:
    def __init__(self):
        self.session_id: bytes = os.urandom(16)
        self.seq_no: int = 0
        # Per-session ephemeral keys (simulates PFS key exchange)
        self.key_256: bytes = os.urandom(32)
        self.key_128: bytes = os.urandom(16)
        self.key_chacha: bytes = os.urandom(32)
        self.controller = AdaptiveController()

    def next_seq(self) -> int:
        self.seq_no += 1
        return self.seq_no

    def key_for(self, cipher_name: str) -> bytes:
        if cipher_name == 'AES-128-GCM':
            return self.key_128
        if cipher_name == 'ChaCha20-Poly1305':
            return self.key_chacha
        return self.key_256   # AES-256-GCM default

def get_or_create_session(session_hex: str | None) -> VPNSession:
    if session_hex and session_hex in _sessions:
        return _sessions[session_hex]
    s = VPNSession()
    _sessions[s.session_id.hex()] = s
    return s

# ── Core encrypt + encapsulate ────────────────────────────────────────────────
def encapsulate(
    plaintext: bytes,
    level: str,
    profile: dict,
    session: VPNSession,
    adapt: dict,
) -> dict:
    """
    Encrypts plaintext and wraps it in a VPN frame.
    Returns a dict with frame bytes (hex) + all metadata for display.
    """
    cipher_name = profile['cipher']
    key   = session.key_for(cipher_name)
    nonce = os.urandom(12)
    seq   = session.next_seq()
    ts_ms = int(time.time() * 1000)
    mtu   = adapt['mtu']

    # ── Encrypt ──────────────────────────────────────────────────────────────
    if cipher_name == 'ChaCha20-Poly1305':
        enc = ChaCha20Poly1305(key)
    else:
        enc = AESGCM(key)

    # AAD = session_id + seq_no (authenticated but not encrypted)
    aad = session.session_id + struct.pack('>I', seq)
    ciphertext = enc.encrypt(nonce, plaintext, aad)

    # Double-encrypt for CRITICAL
    outer_nonce = b''
    if profile.get('double'):
        outer_key   = os.urandom(32)
        outer_nonce = os.urandom(12)
        outer_enc   = AESGCM(outer_key)
        ciphertext  = outer_enc.encrypt(outer_nonce, ciphertext, aad)

    # ── Build flags byte ─────────────────────────────────────────────────────
    flags = 0
    if profile.get('double'):   flags |= 0x01
    if profile.get('pfs'):      flags |= 0x02
    if adapt['force_tcp'] or profile.get('proto') == 'TCP': flags |= 0x04
    if profile.get('cert_pin'): flags |= 0x08

    # ── Assemble frame ───────────────────────────────────────────────────────
    cipher_id  = CIPHER_ID.get(cipher_name, 0x01)
    label_id   = LABEL_ID.get(level, 0x01)
    frame_len  = len(ciphertext)

    header = struct.pack(
        '>4sBBH16sIBB12sHH',
        MAGIC,                      # 4s  magic
        VERSION,                    # B   version
        flags,                      # B   flags
        frame_len & 0xFFFF,         # H   frame_len (lower 16 bits)
        session.session_id,         # 16s session_id
        seq,                        # I   seq_no
        label_id,                   # B   sensitivity label
        cipher_id,                  # B   cipher_id
        nonce,                      # 12s nonce
        mtu,                        # H   mtu
        len(outer_nonce),           # H   outer_nonce_len
    )
    # append 8-byte timestamp separately (avoids struct alignment issues)
    header += ts_ms.to_bytes(8, 'big')

    frame = header + (outer_nonce if outer_nonce else b'') + ciphertext

    return {
        'frame_hex':      frame[:64].hex(),   # first 64 bytes shown in UI
        'frame_len':      len(frame),
        'seq_no':         seq,
        'session_id':     session.session_id.hex()[:16] + '…',
        'nonce_hex':      nonce.hex(),
        'cipher':         cipher_name,
        'cipher_id':      hex(cipher_id),
        'label_id':       hex(label_id),
        'flags':          f'0x{flags:02X}',
        'flags_decoded':  _decode_flags(flags),
        'mtu':            mtu,
        'double_enc':     bool(profile.get('double')),
        'proto':          'TCP' if (flags & 0x04) else 'UDP',
        'payload_bytes':  len(plaintext),
        'encrypted_bytes': len(ciphertext),
        'overhead_bytes': len(frame) - len(ciphertext),
        'ts_ms':          ts_ms,
    }

def _decode_flags(f: int) -> list[str]:
    out = []
    if f & 0x01: out.append('DOUBLE_ENC')
    if f & 0x02: out.append('PFS')
    if f & 0x04: out.append('TCP')
    if f & 0x08: out.append('CERT_PIN')
    return out or ['UDP']
