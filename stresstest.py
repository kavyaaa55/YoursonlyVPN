"""
Adaptive VPN — Real HTTP Stress Test
Architecture:
  [Packet Generator] → real HTTP → [VPN Client (classify+encrypt)] 
       → [Tunnel] → [VPN Server (decrypt)] → [Fake Internet Server]

Run order:
  Terminal 1: python stress_test_http.py server     # fake internet
  Terminal 2: python stress_test_http.py vpn        # vpn server
  Terminal 3: python stress_test_http.py test        # run stress test

Requirements:
  pip install aiohttp fastapi uvicorn cryptography httpx
"""

import asyncio
import sys
import time
import random
import json
import statistics
import hashlib
import os
import hmac
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import re

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

FAKE_INTERNET_PORT = 8888   # Fake websites run here
VPN_SERVER_PORT    = 9999   # VPN server (decrypt + forward)
VPN_CLIENT_PORT    = 7777   # VPN client (classify + encrypt)

SHARED_SECRET = b"adaptive_vpn_shared_secret_key_32b"  # 32 bytes for AES
NODES         = 100
PACKETS_EACH  = 50

# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFIER (same as before)
# ══════════════════════════════════════════════════════════════════════════════

LEVEL_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

DOMAIN_RULES = {
    'uidai.fake':        'CRITICAL',
    'incometax.fake':    'CRITICAL',
    'sbi.fake':          'CRITICAL',
    'hdfcbank.fake':     'CRITICAL',
    'icicibank.fake':    'CRITICAL',
    'paytm.fake':        'HIGH',
    'phonepe.fake':      'HIGH',
    'amazon.fake':       'HIGH',
    'flipkart.fake':     'HIGH',
    'gmail.fake':        'MEDIUM',
    'github.fake':       'MEDIUM',
    'linkedin.fake':     'MEDIUM',
    'youtube.fake':      'LOW',
    'netflix.fake':      'LOW',
    'spotify.fake':      'LOW',
    'steam.fake':        'LOW',
    'twitch.fake':       'LOW',
}

CONTENT_PATTERNS = [
    (re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b'),                        'CRITICAL', 'Aadhaar'),
    (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),                      'CRITICAL', 'PAN Card'),
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),                    'CRITICAL', 'Visa Card'),
    (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),                       'HIGH',     'IFSC'),
    (re.compile(r'[\w.]+@(paytm|oksbi|okaxis|ybl|okhdfcbank)'),     'HIGH',     'UPI ID'),
    (re.compile(r'\+91[\-\s]?[6-9]\d{9}\b'),                        'HIGH',     'Indian Phone'),
    (re.compile(r'\b(cvv|otp|pin|password|passwd|secret)\b', re.I), 'HIGH',     'Credential'),
    (re.compile(r'[\w.\-]+@[\w.\-]+\.[a-z]{2,}'),                   'MEDIUM',   'Email'),
]

PATH_RULES = [
    ('/payment', 'CRITICAL'), ('/transfer', 'CRITICAL'), ('/otp', 'CRITICAL'),
    ('/login',   'HIGH'),     ('/auth',     'HIGH'),      ('/kyc',    'HIGH'),
    ('/upload',  'MEDIUM'),   ('/api/',     'MEDIUM'),
]

def _higher(a, b):
    if a is None: return b
    if b is None: return a
    return b if LEVEL_ORDER.index(b) > LEVEL_ORDER.index(a) else a

def classify(url=None, method='GET', path='/', headers=None, body=None):
    headers = headers or {}
    result  = None
    layers  = 0
    reason  = 'Default LOW'

    # Layer 1 — domain
    if url:
        layers += 1
        domain = url.lower().replace('http://', '').replace('https://', '').split('/')[0]
        if domain in DOMAIN_RULES:
            result = _higher(result, DOMAIN_RULES[domain])
            reason = f'L1: {domain}'
        if result == 'CRITICAL':
            return {'level': result, 'reason': reason, 'layers': layers}

    # Layer 2 — metadata
    layers += 1
    if method.upper() in ('POST', 'PUT'): result = _higher(result, 'MEDIUM')
    for kw, level in PATH_RULES:
        if kw in path.lower():
            result = _higher(result, level); reason = f'L2: path {kw}'; break
    if result == 'CRITICAL':
        return {'level': result, 'reason': reason, 'layers': layers}

    # Layer 3 — content
    if body:
        layers += 1
        for pat, level, name in CONTENT_PATTERNS:
            if pat.search(body):
                result = _higher(result, level); reason = f'L3: {name}'
                if result == 'CRITICAL': break

    return {'level': result or 'LOW', 'reason': reason, 'layers': layers}


# ══════════════════════════════════════════════════════════════════════════════
# ENCRYPTION (AES-256-GCM for CRITICAL/HIGH, ChaCha20 for LOW)
# ══════════════════════════════════════════════════════════════════════════════

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

CIPHER_PROFILES = {
    'CRITICAL': {'algo': 'AES-256-GCM',       'key_len': 32},
    'HIGH':     {'algo': 'AES-256-GCM',       'key_len': 32},
    'MEDIUM':   {'algo': 'AES-128-GCM',       'key_len': 16},
    'LOW':      {'algo': 'ChaCha20-Poly1305',  'key_len': 32},
}

def derive_key(level: str, length: int) -> bytes:
    """Derive a session key from shared secret + level."""
    return hashlib.pbkdf2_hmac('sha256', SHARED_SECRET, level.encode(), 1, dklen=length)

def encrypt_packet(level: str, plaintext: bytes) -> bytes:
    """Encrypt plaintext. Returns: [level_byte][nonce][ciphertext]"""
    profile = CIPHER_PROFILES[level]
    key     = derive_key(level, profile['key_len'])
    nonce   = os.urandom(12)

    if profile['algo'] == 'ChaCha20-Poly1305':
        ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    else:
        ct = AESGCM(key).encrypt(nonce, plaintext, None)

    level_byte = LEVEL_ORDER.index(level).to_bytes(1, 'big')
    return level_byte + nonce + ct

def decrypt_packet(data: bytes) -> Tuple[str, bytes]:
    """Decrypt. Returns: (level, plaintext)"""
    level_idx = data[0]
    level     = LEVEL_ORDER[level_idx]
    nonce     = data[1:13]
    ct        = data[13:]
    profile   = CIPHER_PROFILES[level]
    key       = derive_key(level, profile['key_len'])

    if profile['algo'] == 'ChaCha20-Poly1305':
        pt = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    else:
        pt = AESGCM(key).decrypt(nonce, ct, None)

    return level, pt


# ══════════════════════════════════════════════════════════════════════════════
# COMPONENT 1 — FAKE INTERNET SERVER  (port 8888)
# Simulates real websites: uidai.fake, sbi.fake, youtube.fake etc.
# ══════════════════════════════════════════════════════════════════════════════

FAKE_SITES = {
    '/uidai/verify':       ('CRITICAL', {'status': 'verified',   'name': 'Ravi Kumar',   'uid_last4': '9012'}),
    '/uidai/ekyc':         ('CRITICAL', {'status': 'kyc_done',   'aadhaar': 'XXXX XXXX 9012'}),
    '/sbi/login':          ('CRITICAL', {'status': 'logged_in',  'account': 'XX7821',    'balance': '₹1,24,500'}),
    '/sbi/transfer':       ('CRITICAL', {'status': 'transferred','ref': 'NEFT20240312001','amount': '₹45,000'}),
    '/hdfc/payment':       ('CRITICAL', {'status': 'paid',       'txn_id': 'HDFC88219321'}),
    '/paytm/pay':          ('HIGH',     {'status': 'success',    'upi_ref': 'PTM2024031200X'}),
    '/phonepe/send':       ('HIGH',     {'status': 'sent',       'vpa': 'user@oksbi'}),
    '/amazon/checkout':    ('HIGH',     {'status': 'order_placed','order_id': 'AMZ-2024-88921'}),
    '/flipkart/payment':   ('HIGH',     {'status': 'paid',       'order_id': 'FK-2024-119832'}),
    '/gmail/compose':      ('MEDIUM',   {'status': 'sent',       'msg_id': 'msg_abc123'}),
    '/github/push':        ('MEDIUM',   {'status': 'pushed',     'commit': 'a1b2c3d'}),
    '/linkedin/message':   ('MEDIUM',   {'status': 'delivered',  'thread_id': 'thr_99821'}),
    '/youtube/watch':      ('LOW',      {'status': 'streaming',  'quality': '1080p', 'cdn': 'AP-south'}),
    '/netflix/stream':     ('LOW',      {'status': 'streaming',  'title': 'Mirzapur S3', 'quality': '4K'}),
    '/spotify/play':       ('LOW',      {'status': 'playing',    'track': 'Kesariya',    'bitrate': '320kbps'}),
    '/steam/matchmaking':  ('LOW',      {'status': 'found',      'match_id': 'csgo_88219','ping': '12ms'}),
    '/twitch/stream':      ('LOW',      {'status': 'live',       'streamer': 'shroud',   'viewers': 48210}),
}

async def run_fake_internet():
    from aiohttp import web

    async def handle(request):
        path   = request.path
        body   = await request.text()
        # Find matching route
        for route, (sensitivity, response_data) in FAKE_SITES.items():
            if route in path:
                return web.json_response({
                    'site':        path,
                    'sensitivity': sensitivity,
                    'response':    response_data,
                    'server':      'fake-internet-v1',
                })
        return web.json_response({'status': 'ok', 'path': path, 'sensitivity': 'UNKNOWN'})

    app = web.Application()
    app.router.add_route('*', '/{path_info:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', FAKE_INTERNET_PORT)
    await site.start()
    print(f"[Fake Internet] Running on http://127.0.0.1:{FAKE_INTERNET_PORT}")
    print(f"[Fake Internet] {len(FAKE_SITES)} fake sites available")
    await asyncio.sleep(99999)


# ══════════════════════════════════════════════════════════════════════════════
# COMPONENT 2 — VPN SERVER  (port 9999)
# Receives encrypted packets → decrypts → forwards to fake internet
# ══════════════════════════════════════════════════════════════════════════════

async def run_vpn_server():
    import aiohttp
    from aiohttp import web

    async def handle_tunnel(request):
        raw      = await request.read()
        # Decrypt
        try:
            level, plaintext = decrypt_packet(raw)
        except Exception as e:
            return web.Response(status=400, text=f"Decrypt failed: {e}")

        # Parse original request from plaintext
        meta     = json.loads(plaintext.decode())
        orig_url = meta['url']
        method   = meta.get('method', 'GET')
        body     = meta.get('body', '')
        headers  = meta.get('headers', {})

        # Forward to fake internet
        target_url = f"http://127.0.0.1:{FAKE_INTERNET_PORT}{orig_url}"
        async with aiohttp.ClientSession() as session:
            async with session.request(method, target_url,
                                       data=body, headers=headers) as resp:
                resp_body = await resp.text()

        # Return decrypted response to VPN client
        return web.Response(
            text=resp_body,
            content_type='application/json',
            headers={'X-Decrypted-Level': level,
                     'X-Cipher': CIPHER_PROFILES[level]['algo']}
        )

    app = web.Application(client_max_size=10*1024*1024)
    app.router.add_post('/tunnel', handle_tunnel)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', VPN_SERVER_PORT)
    await site.start()
    print(f"[VPN Server]    Running on http://127.0.0.1:{VPN_SERVER_PORT}")
    print(f"[VPN Server]    Decrypt → Forward to Fake Internet")
    await asyncio.sleep(99999)


# ══════════════════════════════════════════════════════════════════════════════
# COMPONENT 3 — VPN CLIENT  (the classify + encrypt + send part)
# This is what each "node" uses
# ══════════════════════════════════════════════════════════════════════════════

async def vpn_client_send(session, url: str, method: str = 'GET',
                          body: str = '', headers: dict = {}) -> dict:
    """
    Full VPN client pipeline:
    1. Classify the request
    2. Encrypt with correct cipher
    3. Send encrypted to VPN server tunnel
    4. Return result
    """
    t0 = time.perf_counter()

    # Step 1: Classify
    path       = '/' + '/'.join(url.split('/')[1:]) if '/' in url else '/'
    cls_result = classify(url=url, method=method, path=path,
                          headers=headers, body=body or None)
    level      = cls_result['level']
    t_classify = time.perf_counter()

    # Step 2: Build packet payload
    payload = json.dumps({
        'url':     url,
        'method':  method,
        'body':    body,
        'headers': headers,
    }).encode()

    # Step 3: Encrypt
    encrypted  = encrypt_packet(level, payload)
    t_encrypt  = time.perf_counter()

    # Step 4: Send to VPN server
    tunnel_url = f"http://127.0.0.1:{VPN_SERVER_PORT}/tunnel"
    async with session.post(tunnel_url, data=encrypted,
                            headers={'Content-Type': 'application/octet-stream'}) as resp:
        response_text = await resp.text()
        cipher_used   = resp.headers.get('X-Cipher', '?')
        decrypted_lvl = resp.headers.get('X-Decrypted-Level', '?')

    t_total = time.perf_counter()

    return {
        'level':          level,
        'reason':         cls_result['reason'],
        'layers':         cls_result['layers'],
        'cipher':         CIPHER_PROFILES[level]['algo'],
        'classify_ms':    (t_classify - t0)       * 1000,
        'encrypt_ms':     (t_encrypt  - t_classify) * 1000,
        'tunnel_ms':      (t_total    - t_encrypt)  * 1000,
        'total_ms':       (t_total    - t0)         * 1000,
        'response':       response_text[:80],
        'server_cipher':  cipher_used,
    }


# ══════════════════════════════════════════════════════════════════════════════
# REAL PACKET TEMPLATES — actual fake-internet URLs with real-world data
# ══════════════════════════════════════════════════════════════════════════════

REAL_PACKETS = [
    # CRITICAL — Gov / Bank
    {'url': '/uidai/verify',   'method': 'POST', 'body': 'uid=2345+6789+1234&name=Ravi+Kumar&dob=1990-06-15',                     'expected': 'CRITICAL'},
    {'url': '/uidai/ekyc',     'method': 'POST', 'body': 'aadhaar=9876+5432+1098&pan=ABCDE1234F&mobile=%2B91+9845123456',         'expected': 'CRITICAL'},
    {'url': '/sbi/login',      'method': 'POST', 'body': 'user=20394857621&password=SBI%40Secure2024&otp=334521',                 'expected': 'CRITICAL'},
    {'url': '/sbi/transfer',   'method': 'POST', 'body': 'from=20394857621&to=50987654321&ifsc=SBIN0003456&amount=75000',         'expected': 'CRITICAL'},
    {'url': '/hdfc/payment',   'method': 'POST', 'body': 'card=4532756279624064&cvv=341&expiry=09%2F27&name=Anjali+Singh',        'expected': 'CRITICAL'},
    # HIGH — Payments
    {'url': '/paytm/pay',      'method': 'POST', 'body': 'vpa=rahul.sharma@oksbi&amount=850&note=Grocery',                       'expected': 'HIGH'},
    {'url': '/phonepe/send',   'method': 'POST', 'body': 'vpa=doctor.mehta@okicici&amount=500&remarks=Consultation',             'expected': 'HIGH'},
    {'url': '/amazon/checkout','method': 'POST', 'body': 'email=priya%40gmail.com&password=Amazon%40Priya2024',                  'expected': 'HIGH'},
    {'url': '/flipkart/payment','method':'POST', 'body': 'card=5425233430109903&cvv=782&expiry=11%2F26',                         'expected': 'CRITICAL'},
    # MEDIUM — General
    {'url': '/gmail/compose',  'method': 'POST', 'body': 'to=boss%40company.com&subject=Q3+Report&body=Please+find+attached',    'expected': 'MEDIUM'},
    {'url': '/github/push',    'method': 'POST', 'body': 'repo=adaptive-vpn&branch=main&commit=Fix+null+pointer+exception',      'expected': 'MEDIUM'},
    {'url': '/linkedin/message','method':'POST', 'body': 'to=recruiter%40infosys.com&msg=Hi+I+am+interested+in+SDE+role',        'expected': 'MEDIUM'},
    # LOW — Streaming / Gaming
    {'url': '/youtube/watch',  'method': 'GET',  'body': '',                                                                     'expected': 'LOW'},
    {'url': '/netflix/stream', 'method': 'GET',  'body': '',                                                                     'expected': 'LOW'},
    {'url': '/spotify/play',   'method': 'GET',  'body': '',                                                                     'expected': 'LOW'},
    {'url': '/steam/matchmaking','method':'POST','body': '{"matchId":"csgo_88219","region":"AP","mode":"competitive"}',          'expected': 'LOW'},
    {'url': '/twitch/stream',  'method': 'GET',  'body': '',                                                                     'expected': 'LOW'},
]


# ══════════════════════════════════════════════════════════════════════════════
# STRESS TEST RUNNER — 100 nodes × 50 packets each
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketResult:
    node_id:      int
    packet_index: int
    expected:     str
    got:          str
    correct:      bool
    classify_ms:  float
    encrypt_ms:   float
    tunnel_ms:    float
    total_ms:     float
    reason:       str
    cipher:       str
    url:          str

async def run_node(node_id: int, packets_per_node: int, session) -> List[PacketResult]:
    results = []
    for i in range(packets_per_node):
        pkt = random.choice(REAL_PACKETS)
        await asyncio.sleep(random.uniform(0, 0.001))  # jitter
        try:
            r = await vpn_client_send(
                session,
                url     = pkt['url'],
                method  = pkt['method'],
                body    = pkt.get('body', ''),
                headers = pkt.get('headers', {}),
            )
            results.append(PacketResult(
                node_id      = node_id,
                packet_index = i,
                expected     = pkt['expected'],
                got          = r['level'],
                correct      = r['level'] == pkt['expected'],
                classify_ms  = r['classify_ms'],
                encrypt_ms   = r['encrypt_ms'],
                tunnel_ms    = r['tunnel_ms'],
                total_ms     = r['total_ms'],
                reason       = r['reason'],
                cipher       = r['cipher'],
                url          = pkt['url'],
            ))
        except Exception as e:
            print(f"  [Node-{node_id:03d}] pkt-{i} ERROR: {e}")
    return results

async def run_stress_test():
    import aiohttp

    print(f"\n  Waiting for servers to be ready...")
    await asyncio.sleep(2)

    print(f"  Starting stress test: {NODES} nodes × {PACKETS_EACH} packets\n")
    t0 = time.perf_counter()

    connector = aiohttp.TCPConnector(limit=200)  # 200 concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks      = [run_node(i, PACKETS_EACH, session) for i in range(NODES)]
        all_results_nested = await asyncio.gather(*tasks)

    total_s = time.perf_counter() - t0
    all_results = [r for node in all_results_nested for r in node]
    print_report(all_results, total_s)


def print_report(results: List[PacketResult], total_s: float):
    total   = len(results)
    correct = sum(1 for r in results if r.correct)

    classify_times = [r.classify_ms for r in results]
    encrypt_times  = [r.encrypt_ms  for r in results]
    tunnel_times   = [r.tunnel_ms   for r in results]
    total_times    = [r.total_ms    for r in results]

    level_counts  = defaultdict(int)
    level_correct = defaultdict(int)
    cipher_counts = defaultdict(int)

    for r in results:
        level_counts[r.got]  += 1
        cipher_counts[r.cipher] += 1
        if r.correct: level_correct[r.got] += 1

    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║       ADAPTIVE VPN — REAL HTTP STRESS TEST REPORT                   ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  CONFIGURATION")
    print(f"  {'─'*67}")
    print(f"  Nodes              : {NODES}")
    print(f"  Packets/node       : {PACKETS_EACH}")
    print(f"  Total packets      : {total}")
    print(f"  Wall time          : {total_s:.2f}s")
    print(f"  Throughput         : {total/total_s:,.0f} req/sec  (real HTTP)")
    print()
    print(f"  ACCURACY")
    print(f"  {'─'*67}")
    print(f"  Correct            : {correct}/{total}  ({correct/total*100:.1f}%)")
    print(f"  Wrong              : {total - correct}")
    print()
    print(f"  LATENCY BREAKDOWN  (each stage separately)")
    print(f"  {'─'*67}")
    print(f"  {'Stage':<18} {'Min':>8} {'Mean':>8} {'P95':>8} {'Max':>8}")
    print(f"  {'─'*18} {'─'*8} {'─'*8} {'─'*8} {'─'*8}")
    for label, times in [
        ('Classify (ms)',  classify_times),
        ('Encrypt  (ms)',  encrypt_times),
        ('Tunnel   (ms)',  tunnel_times),
        ('TOTAL    (ms)',  total_times),
    ]:
        s = sorted(times)
        print(f"  {label:<18} {min(times):>8.3f} {statistics.mean(times):>8.3f}"
              f" {s[int(len(s)*.95)]:>8.3f} {max(times):>8.3f}")
    print()
    print(f"  SENSITIVITY DISTRIBUTION")
    print(f"  {'─'*67}")
    print(f"  {'Level':<12} {'Count':>6} {'%':>6} {'Accuracy':>10}  Chart")
    for lvl in ['CRITICAL','HIGH','MEDIUM','LOW']:
        c   = level_counts[lvl]
        if not c: continue
        acc = level_correct[lvl]/c*100
        pct = c/total*100
        bar = '█' * int(pct/3)
        print(f"  {lvl:<12} {c:>6} {pct:>5.1f}% {acc:>9.1f}%  {bar}")
    print()
    print(f"  CIPHER USAGE  (encryption algo per packet)")
    print(f"  {'─'*67}")
    for cipher, count in sorted(cipher_counts.items(), key=lambda x: -x[1]):
        pct = count/total*100
        bar = '█' * int(pct/3)
        print(f"  {cipher:<25} {count:>6} ({pct:>5.1f}%)  {bar}")
    print()
    wrong = [r for r in results if not r.correct]
    if wrong:
        print(f"  MISCLASSIFICATIONS ({len(wrong)})")
        print(f"  {'─'*67}")
        for r in wrong[:8]:
            print(f"  Node-{r.node_id:03d} {r.url:<25} exp={r.expected:<9} got={r.got}")
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║  TEST COMPLETE  — Real HTTP requests through encrypt/decrypt tunnel  ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    with open('real_http_report.json', 'w') as f:
        json.dump({
            'total': total, 'correct': correct,
            'accuracy_pct': correct/total*100,
            'throughput_rps': total/total_s,
            'latency': {
                'classify_mean_ms': statistics.mean(classify_times),
                'encrypt_mean_ms':  statistics.mean(encrypt_times),
                'tunnel_mean_ms':   statistics.mean(tunnel_times),
                'total_mean_ms':    statistics.mean(total_times),
                'total_p99_ms':     sorted(total_times)[int(len(total_times)*.99)],
            },
            'by_level': {lvl: {'count': level_counts[lvl],
                               'accuracy': level_correct[lvl]/level_counts[lvl]*100
                               if level_counts[lvl] else 0}
                         for lvl in ['CRITICAL','HIGH','MEDIUM','LOW']},
            'ciphers': dict(cipher_counts),
        }, f, indent=2)
    print(f"\n  📄 JSON report: real_http_report.json\n")


# ══════════════════════════════════════════════════════════════════════════════
# COMBINED RUNNER — starts all 3 components in one process
# ══════════════════════════════════════════════════════════════════════════════

async def run_all():
    """Starts fake internet + VPN server + stress test all at once."""
    print("\n  Adaptive VPN — Real HTTP Stress Test")
    print("  Starting all components...\n")

    # Start fake internet + VPN server as background tasks
    server_task1 = asyncio.create_task(run_fake_internet())
    server_task2 = asyncio.create_task(run_vpn_server())

    # Give servers 1s to boot
    await asyncio.sleep(1)

    # Run stress test
    await run_stress_test()

    # Cancel servers
    server_task1.cancel()
    server_task2.cancel()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'

    if mode == 'server':
        print("[Mode] Fake Internet only")
        asyncio.run(run_fake_internet())
    elif mode == 'vpn':
        print("[Mode] VPN Server only")
        asyncio.run(run_vpn_server())
    elif mode == 'test':
        print("[Mode] Stress Test only (servers must be running)")
        asyncio.run(run_stress_test())
    else:
        # Default: run everything in one process
        asyncio.run(run_all())