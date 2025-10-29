import socket
import json
import math
import secrets
import hashlib
from dataclasses import dataclass

# ---------- Utility ----------
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1=egcd(b,a%b)
    return (g,y1,x1-(a//b)*y1)

def invmod(a,m):
    g,x,y=egcd(a,m)
    if g!=1: raise Exception("No modular inverse")
    return x%m

def lcm(a,b): return abs(a*b)//math.gcd(a,b)

def generate_prime(bits=128):
    while True:
        p = secrets.randbits(bits) | 1 | (1<<(bits-1))
        for _ in range(10):
            a = secrets.randbelow(p-2)+2
            if pow(a,p-1,p)!=1:
                break
        else:
            return p

# ---------- Paillier ----------
@dataclass
class PaillierPublicKey:
    n:int; n2:int; g:int
@dataclass
class PaillierPrivateKey:
    lam:int; mu:int

def paillier_keygen(bits=256):
    p,q=generate_prime(bits//2),generate_prime(bits//2)
    n=p*q; n2=n*n; g=n+1
    lam=lcm(p-1,q-1)
    def L(u): return (u-1)//n
    mu=invmod(L(pow(g,lam,n2)),n)
    return PaillierPublicKey(n,n2,g), PaillierPrivateKey(lam,mu)

def paillier_decrypt(pub,priv,c):
    def L(u): return (u-1)//pub.n
    return (L(pow(c,priv.lam,pub.n2))*priv.mu)%pub.n

# ---------- RSA ----------
@dataclass
class RSAKeyPair:
    n:int; e:int; d:int

def rsa_keygen(bits=512):
    p,q=generate_prime(bits//2),generate_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1); e=65537
    d=invmod(e,phi)
    return RSAKeyPair(n,e,d)

def rsa_sign(key,data:bytes):
    h=int.from_bytes(hashlib.sha256(data).digest(),'big')
    return pow(h,key.d,key.n)

def rsa_verify(key,data:bytes,sig:int):
    h=int.from_bytes(hashlib.sha256(data).digest(),'big')
    return pow(sig,key.e,key.n)==(h%key.n)

# ---------- Server ----------
class PaymentGateway:
    def __init__(self):
        self.paillier_pub, self.paillier_priv = paillier_keygen()
        self.rsa_keys = rsa_keygen()
        self.summary = []

    def start(self, host="127.0.0.1", port=5000):
        s = socket.socket()
        s.bind((host, port))
        s.listen(5)
        print(f"\n[SERVER] Listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            print(f"\n[SERVER] Connected with {addr}")
            conn.send(json.dumps({
                "pubkey": (self.paillier_pub.n, self.paillier_pub.g)
            }).encode())

            data = json.loads(conn.recv(8192).decode())
            seller = data["seller"]
            transactions = data["transactions"]
            total_enc = 1

            for c in transactions:
                total_enc = (total_enc * c) % self.paillier_pub.n2

            total_dec = paillier_decrypt(self.paillier_pub, self.paillier_priv, total_enc)
            total_dec_inr = total_dec / 100.0

            self.summary.append({
                "seller": seller,
                "encrypted_transactions": transactions,
                "total_encrypted": total_enc,
                "total_decrypted": total_dec_inr
            })

            print(f"[SERVER] Seller {seller} total = ₹{total_dec_inr:.2f}")
            conn.send(b"Transactions received successfully!")
            conn.close()

    def show_summary(self):
        print("\n===== TRANSACTION SUMMARY =====")
        for s in self.summary:
            print(json.dumps(s, indent=4))

    def sign_summary(self):
        data=json.dumps(self.summary,sort_keys=True).encode()
        sig=rsa_sign(self.rsa_keys,data)
        print(f"\nDigital Signature: {sig}")
        print("Verification:", rsa_verify(self.rsa_keys,data,sig))

# ---------- Menu ----------
def main():
    gateway = PaymentGateway()

    while True:
        print("""
========== PAYMENT GATEWAY MENU ==========
1. Start Server
2. Show Transaction Summary
3. Sign & Verify Summary
4. Exit
""")
        ch = input("Enter choice: ")
        if ch == "1": gateway.start()
        elif ch == "2": gateway.show_summary()
        elif ch == "3": gateway.sign_summary()
        elif ch == "4": break
        else: print("Invalid choice.")

if __name__ == "__main__":
    main()
