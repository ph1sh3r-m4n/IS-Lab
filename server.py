import socket
import json
import math
import secrets
import hashlib

# ---------- Utility ----------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def generate_prime(bits=128):
    while True:
        p = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        for _ in range(10):
            a = secrets.randbelow(p - 2) + 2
            if pow(a, p - 1, p) != 1:
                break
        else:
            return p

# ---------- Paillier ----------
def paillier_keygen(bits=256):
    p, q = generate_prime(bits // 2), generate_prime(bits // 2)
    n = p * q
    n2 = n * n
    g = n + 1
    lam = lcm(p - 1, q - 1)
    def L(u): return (u - 1) // n
    mu = invmod(L(pow(g, lam, n2)), n)
    return (n, n2, g, lam, mu)

def paillier_decrypt(n, n2, lam, mu, c):
    def L(u): return (u - 1) // n
    return (L(pow(c, lam, n2)) * mu) % n

# ---------- RSA ----------
def rsa_keygen(bits=512):
    p, q = generate_prime(bits // 2), generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = invmod(e, phi)
    return (n, e, d)

def rsa_sign(n, d, data: bytes):
    h = int.from_bytes(hashlib.sha256(data).digest(), 'big')
    return pow(h, d, n)

def rsa_verify(n, e, data: bytes, sig: int):
    h = int.from_bytes(hashlib.sha256(data).digest(), 'big')
    return pow(sig, e, n) == (h % n)

# ---------- Global Variables ----------
summary = []
paillier_keys = None
rsa_keys = None

# ---------- Server ----------
def start_server():
    global paillier_keys, rsa_keys, summary

    if paillier_keys is None:
        paillier_keys = paillier_keygen()
    if rsa_keys is None:
        rsa_keys = rsa_keygen()

    n, n2, g, lam, mu = paillier_keys

    s = socket.socket()
    s.bind(("127.0.0.1", 5000))
    s.listen(5)
    print("\n[SERVER] Listening on 127.0.0.1:5000")

    while True:
        conn, addr = s.accept()
        print(f"\n[SERVER] Connected with {addr}")
        conn.send(json.dumps({
            "pubkey": (n, g)
        }).encode())

        data = json.loads(conn.recv(8192).decode())
        seller = data["seller"]
        transactions = data["transactions"]

        # Homomorphic addition
        total_enc = 1
        for c in transactions:
            total_enc = (total_enc * c) % n2

        total_dec = paillier_decrypt(n, n2, lam, mu, total_enc)
        total_dec_inr = total_dec / 100.0

        summary.append({
            "seller": seller,
            "encrypted_transactions": transactions,
            "total_encrypted": total_enc,
            "total_decrypted": total_dec_inr
        })

        print(f"[SERVER] Seller {seller} total = ₹{total_dec_inr:.2f}")
        conn.send(b"Transactions received successfully!")
        conn.close()

def show_summary():
    print("\n===== TRANSACTION SUMMARY =====")
    for s in summary:
        print(json.dumps(s, indent=4))

def sign_and_verify_summary():
    global rsa_keys
    if rsa_keys is None:
        rsa_keys = rsa_keygen()

    n, e, d = rsa_keys
    data = json.dumps(summary, sort_keys=True).encode()
    sig = rsa_sign(n, d, data)
    print(f"\nDigital Signature: {sig}")
    print("Verification:", rsa_verify(n, e, data, sig))

# ---------- Menu ----------
def main():
    while True:
        print("""
========== PAYMENT GATEWAY MENU ==========
1. Start Server
2. Show Trans
