import hashlib
import random
import time

MAGIC_BYTE = 48
XGNARLY_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CANVAS_DEFAULT = 1938040196
SDK_VERSION = "5.1.3-ZTCA"
SCM_VERSION = "1.0.0.368"

PRNG_INIT_WORDS = [
    2517678443, 2718276124, 3212677781, 2633865432,
    217618912, 2931180889, 1498001188, 2157053261,
    211147047, 185100057, 2903579748, 3732962506
]
B0 = 0xFFFFFFFF

def u32(x): return x & 0xFFFFFFFF
def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def quarter_round(s, a, b, c, d):
    s[a] = u32(s[a] + s[b])
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = u32(s[c] + s[d])
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = u32(s[a] + s[b])
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = u32(s[c] + s[d])
    s[b] = rotl(s[b] ^ s[c], 7)

def chacha_block(state, rounds):
    working = state[:16]
    r = 0
    while r < rounds:
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        r += 1
        if r >= rounds: break
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 12, 13)
        quarter_round(working, 3, 4, 13, 14)
        r += 1
    return [u32(working[i] + state[i]) for i in range(16)]

def chacha_encrypt(key, rounds, plaintext):
    result = []
    state = PRNG_INIT_WORDS[:12] + [0, 0, 0, 0]
    for i in range(0, len(plaintext), 64):
        block = chacha_block(state, rounds)
        for j in range(64):
            if i + j < len(plaintext):
                result.append(chr(ord(plaintext[i + j]) ^ ((block[j // 4] >> ((j % 4) * 8)) & 0xFF)))
        state[12] = u32(state[12] + 1)
    return "".join(result)

def b64_encode(data):
    out = []
    n = len(data)
    for i in range(0, n, 3):
        if i + 2 < n:
            b = (ord(data[i]) << 16) | (ord(data[i+1]) << 8) | ord(data[i+2])
            out.append(XGNARLY_B64[(b >> 18) & 0x3F])
            out.append(XGNARLY_B64[(b >> 12) & 0x3F])
            out.append(XGNARLY_B64[(b >> 6) & 0x3F])
            out.append(XGNARLY_B64[b & 0x3F])
        elif i + 1 < n:
            b = (ord(data[i]) << 16) | (ord(data[i+1]) << 8)
            out.append(XGNARLY_B64[(b >> 18) & 0x3F])
            out.append(XGNARLY_B64[(b >> 12) & 0x3F])
            out.append(XGNARLY_B64[(b >> 6) & 0x3F])
            out.append('=')
        else:
            b = ord(data[i]) << 16
            out.append(XGNARLY_B64[(b >> 18) & 0x3F])
            out.append(XGNARLY_B64[(b >> 12) & 0x3F])
            out.append('==')
    return ''.join(out)

def int_to_bytes(v):
    if v < 255 * 255:
        return [(v >> 8) & 0xFF, v & 0xFF]
    return [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]

def str_to_be_u32(s):
    buf = s.encode()[:4]
    acc = 0
    for b in buf:
        acc = (acc << 8) | b
    return acc & 0xFFFFFFFF

def build_payload(fields, order):
    out = [len(order)]
    for k in order:
        v = fields[k]
        out.append(k)
        vb = int_to_bytes(v) if isinstance(v, int) else list(v.encode())
        out += int_to_bytes(len(vb))
        out += vb
    return "".join(chr(b) for b in out)

class GnarlyPRNG:
    def __init__(self, ts_ms=None):
        ts = (int(time.time() * 1000) if ts_ms is None else ts_ms) & 0xFFFFFFFF
        self._state = PRNG_INIT_WORDS[:12] + [B0 & ts, random.getrandbits(32), random.getrandbits(32), random.getrandbits(32)]
        self._idx = 0
    def next_u32(self):
        block = chacha_block(self._state, 8)
        val = block[self._idx]
        if self._idx == 7:
            self._state[12] = u32(self._state[12] + 1)
            self._idx = 0
        else:
            self._idx += 1
        return val

def compute_xgnarly(query_string, ua, body="", ts_ms=None):
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    ts_sec = ts_ms // 1000
    
    fields = {}
    order = []
    def put(k, v):
        fields[k] = v
        if k not in order:
            order.append(k)
    
    put(1, 1)
    put(2, 14)
    put(3, hashlib.md5(query_string.encode()).hexdigest())
    put(4, hashlib.md5(body.encode()).hexdigest())
    put(5, hashlib.md5(ua.encode()).hexdigest())
    put(6, ts_sec)
    put(7, CANVAS_DEFAULT)
    put(8, ts_ms % 2147483648)
    put(9, SDK_VERSION)
    put(10, SCM_VERSION)
    put(11, 1)
    put(13, "web")
    put(14, "chromium")
    
    inner = 0
    for i in range(1, 12):
        v = fields[i]
        inner ^= v if isinstance(v, int) else str_to_be_u32(v)
    put(12, inner & 0xFFFFFFFF)
    
    outer = 0
    for k in order:
        v = fields[k]
        if isinstance(v, int):
            outer ^= v
    put(0, outer & 0xFFFFFFFF)
    
    payload = build_payload(fields, order)
    
    prng = GnarlyPRNG(ts_ms)
    key_words = []
    key_bytes = []
    round_acc = 0
    
    for _ in range(12):
        w = prng.next_u32()
        key_words.append(w)
        round_acc = (round_acc + (w & 0xF)) & 0xF
        key_bytes += [w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF]
    
    rounds = round_acc + 5
    encrypted = chacha_encrypt(key_words, rounds, payload)
    
    pos = 0
    for b in key_bytes:
        pos = (pos + b) % (len(encrypted) + 1)
    for c in encrypted:
        pos = (pos + ord(c)) % (len(encrypted) + 1)
    
    key_str = "".join(chr(b) for b in key_bytes)
    
    result = b64_encode(chr(MAGIC_BYTE) + encrypted[:pos] + key_str + encrypted[pos:])
    
    result = result.replace('+', '-')
    
    # Ensure it ends with '=='
    if not result.endswith('=='):
        if result.endswith('='):
            result += '='
        else:
            result += '=='
    
    return result

if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "aid=1988&app_name=tiktok_web"
    ua = sys.argv[2] if len(sys.argv) > 2 else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    body = sys.argv[3] if len(sys.argv) > 3 else ""
    
    result = compute_xgnarly(query, ua, body)
    print(result)
