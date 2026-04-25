# api/server.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import json, time
from rule_engine.classifier import classify
from encryption.cipher_selector import PROFILES
from tunnel.vpn_tunnel import (
    get_or_create_session, encapsulate, AdaptiveController
)

app = FastAPI(title='Adaptive VPN API')
app.add_middleware(CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

# ── Models ───────────────────────────────────────────────────────────────────
class ClassifyRequest(BaseModel):
    url:     Optional[str] = None
    method:  str = 'GET'
    path:    str = '/'
    headers: Dict[str, str] = {}
    body:    Optional[str] = None
    message: Optional[str] = None
    is_msg:  bool = False

class TunnelSendRequest(BaseModel):
    # same fields as classify, plus session tracking + measured RTT
    url:        Optional[str] = None
    method:     str = 'GET'
    path:       str = '/'
    headers:    Dict[str, str] = {}
    body:       Optional[str] = None
    message:    Optional[str] = None
    is_msg:     bool = False
    session_id: Optional[str] = None   # hex; None = create new session
    client_rtt: Optional[float] = None # last measured RTT from client (ms)

# ── /classify — plain classification only ────────────────────────────────────
@app.post('/classify')
async def classify_request(req: ClassifyRequest):
    result = classify(
        url=req.url, method=req.method, path=req.path,
        headers=req.headers, body=req.body,
        message=req.message, is_msg=req.is_msg,
    )
    result['profile'] = PROFILES[result['level']]
    return result

# ── /tunnel/send — full VPN pipeline ─────────────────────────────────────────
@app.post('/tunnel/send')
async def tunnel_send(req: TunnelSendRequest):
    """
    Full pipeline:
      1. Classify sensitivity (4-layer rule engine)
      2. Feed RTT into adaptive controller
      3. Adaptive controller decides cipher / MTU / protocol
      4. Encrypt + encapsulate into a real VPN frame
      5. Return frame metadata + decrypted echo (simulates server-side decap)
    """
    t_start = time.perf_counter()

    # 1. Classify
    classification = classify(
        url=req.url, method=req.method, path=req.path,
        headers=req.headers, body=req.body,
        message=req.message, is_msg=req.is_msg,
    )
    level   = classification['level']
    profile = PROFILES[level]

    # 2. Session + adaptive controller
    session = get_or_create_session(req.session_id)
    if req.client_rtt is not None:
        session.controller.record_rtt(req.client_rtt)

    adapt = session.controller.adapt(level)

    # 3. Encapsulate
    plaintext = (req.body or req.message or req.url or 'ping').encode('utf-8')
    frame_info = encapsulate(plaintext, level, profile, session, adapt)

    proc_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        # Classification
        'level':          level,
        'reason':         classification['reason'],
        'layers_checked': classification['layers_checked'],
        'profile':        profile,

        # Adaptive controller output
        'adaptive': {
            'adapted_level':  adapt['adapted_level'],
            'force_tcp':      adapt['force_tcp'],
            'mtu':            adapt['mtu'],
            'avg_rtt_ms':     adapt['avg_rtt_ms'],
            'jitter_ms':      adapt['jitter_ms'],
            'adapt_reason':   adapt['adapt_reason'],
            'total_packets':  adapt['total_packets'],
        },

        # VPN frame metadata
        'tunnel': {
            'session_id':      frame_info['session_id'],
            'seq_no':          frame_info['seq_no'],
            'frame_hex':       frame_info['frame_hex'],
            'frame_len':       frame_info['frame_len'],
            'nonce_hex':       frame_info['nonce_hex'],
            'cipher':          frame_info['cipher'],
            'cipher_id':       frame_info['cipher_id'],
            'label_id':        frame_info['label_id'],
            'flags':           frame_info['flags'],
            'flags_decoded':   frame_info['flags_decoded'],
            'mtu':             frame_info['mtu'],
            'proto':           frame_info['proto'],
            'double_enc':      frame_info['double_enc'],
            'payload_bytes':   frame_info['payload_bytes'],
            'encrypted_bytes': frame_info['encrypted_bytes'],
            'overhead_bytes':  frame_info['overhead_bytes'],
        },

        # Server-side processing time
        'proc_ms':        proc_ms,
        'new_session_id': session.session_id.hex(),
    }

# ── /tunnel/session — inspect a session's controller state ───────────────────
@app.get('/tunnel/session/{session_hex}')
async def get_session(session_hex: str):
    from tunnel.vpn_tunnel import _sessions
    s = _sessions.get(session_hex)
    if not s:
        return {'error': 'session not found'}
    c = s.controller
    return {
        'session_id':    session_hex,
        'seq_no':        s.seq_no,
        'total_packets': c.total_packets,
        'avg_rtt_ms':    round(c.avg_rtt, 1),
        'jitter_ms':     round(c.jitter, 1),
        'rtt_window':    [round(r, 1) for r in c.rtt_window],
    }

# ── /profiles ────────────────────────────────────────────────────────────────
@app.get('/profiles')
async def get_profiles():
    return PROFILES

# ── /health ──────────────────────────────────────────────────────────────────
@app.get('/health')
async def health():
    return {'status': 'ok'}

# ── WebSocket — real-time feed ────────────────────────────────────────────────
@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            data = await ws.receive_text()
            req  = json.loads(data)
            result = classify(**req)
            result['profile'] = PROFILES[result['level']]
            await ws.send_text(json.dumps(result))
    except WebSocketDisconnect:
        pass

# uvicorn api.server:app --reload --port 8000
