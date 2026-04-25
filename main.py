# main.py
from rule_engine.classifier import classify
from encryption.cipher_selector import encrypt_payload

def process_packet(url, method='GET', path='/', headers={}, body=None):
    # Step 1: Classify
    result   = classify(url=url, method=method, path=path, headers=headers, body=body)
    level    = result['level']

    # Step 2: Encrypt
    payload  = (body or '').encode()
    enc      = encrypt_payload(level, payload)

    print(f'[{level}] {url or path}')
    print(f'  Reason  : {result["reason"]}')
    print(f'  Cipher  : {enc["profile"]["cipher"]}')
    print(f'  Protocol: {enc["profile"]["proto"]}')
    return level, enc

if __name__ == '__main__':
    # Test cases
    process_packet('https://uidai.gov.in/verify')
    process_packet('https://steampowered.com/game/123')
    process_packet('https://api.example.com/login',
        method='POST', body='{"password": "mySecret123"}')
