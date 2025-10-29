import hashlib, json, math, secrets, pprint
from dataclasses import dataclass

# ===================== Utility Functions =====================
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def invmod(a, m):
    g,x,y = egcd(a,m)
    if g!=1: raise Exception("No modular inverse")
    return x % m

def lcm(a,b): return abs(a*b)//math.gcd(a,b)

def is_probable_prime(n, k=8):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n%p==0:
            return n==p
    s, d = 0, n-1
    while d%2==0:
        d//=2; s+=1
    for _ in range(k):
        a = secrets.randbelow(n-3)+2
        x = pow(a,d,n)
        if x in (1,n-1): continue
        for _ in range(s-1):
            x = pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def generate_prime(bits=256):
    while True:
        p = secrets.randbits(bits) | 1 | (1<<(bits-1))
        if is_probable_prime(p): return p

# ===================== Paillier =====================
@dataclass
class PaillierPublicKey:
    n:int; n2:int; g:int
@dataclass
class PaillierPrivateKey:
    lam:int; mu:int

def paillier_keygen(bits=512):
    p,q = generate_prime(bits//2), generate_prime(bits//2)
    while q==p: q = generate_prime(bits//2)
    n = p*q; n2 = n*n; g = n+1
    lam = lcm(p-1,q-1)
    def L(u): return (u-1)//n
    u = pow(g,lam,n2)
    mu = invmod(L(u), n)
    return PaillierPublicKey(n,n2,g), PaillierPrivateKey(lam,mu)

def paillier_encrypt(pub, m):
    r = secrets.randbelow(pub.n-1)+1
    return (pow(pub.g,m,pub.n2)*pow(r,pub.n,pub.n2))%pub.n2

def paillier_decrypt(pub, priv, c):
    def L(u): return (u-1)//pub.n
    u = pow(c, priv.lam, pub.n2)
    return (L(u)*priv.mu)%pub.n

# ===================== RSA (Sign/Verify) =====================
@dataclass
class RSAKeyPair:
    n:int; e:int; d:int

def rsa_keygen(bits=1024):
    p,q = generate_prime(bits//2), generate_prime(bits//2)
    while q==p: q = generate_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1); e=65537
    if math.gcd(e,phi)!=1:
        e=3
        while math.gcd(e,phi)!=1: e+=2
    d=invmod(e,phi)
    return RSAKeyPair(n,e,d)

def rsa_sign(key, data:bytes):
    h = int.from_bytes(hashlib.sha256(data).digest(),'big')
    return pow(h,key.d,key.n)

def rsa_verify(key, data:bytes, sig:int):
    h = int.from_bytes(hashlib.sha256(data).digest(),'big')
    return pow(sig,key.e,key.n)==(h%key.n)

# ===================== Seller System =====================
class SellerSystem:
    def __init__(self):
        self.sellers = {}
        self.paillier_pub, self.paillier_priv = paillier_keygen()
        self.rsa_keys = rsa_keygen()
        self.signature = None

    def add_seller(self):
        name = input("Enter seller name: ").strip()
        if name in self.sellers:
            print("Seller already exists!")
            return
        self.sellers[name] = []
        print("Seller added.")

    def add_transaction(self):
        name = input("Enter seller name: ").strip()
        if name not in self.sellers:
            print("Seller not found.")
            return
        amt = float(input("Enter transaction amount (INR): "))
        self.sellers[name].append(amt)
        print("Transaction added.")

    def encrypt_transactions(self):
        self.summary = []
        for seller, txns in self.sellers.items():
            enc_product = 1
            tx_list=[]
            for amt in txns:
                paisa=int(round(amt*100))
                c=paillier_encrypt(self.paillier_pub,paisa)
                tx_list.append((amt,paisa,c))
                enc_product=(enc_product*c)%self.paillier_pub.n2
            total=paillier_decrypt(self.paillier_pub,self.paillier_priv,enc_product)/100.0
            self.summary.append({
                "Seller":seller,
                "Transactions":tx_list,
                "TotalEncrypted":enc_product,
                "TotalDecrypted":total
            })
        print("All transactions encrypted and totals computed.")

    def show_summary(self):
        pp=pprint.PrettyPrinter(indent=4)
        for s in self.summary:
            print(f"\nSeller: {s['Seller']}")
            for i,(amt,paisa,c) in enumerate(s['Transactions'],1):
                print(f"  Tx{i}: {amt} INR ({paisa} paisa)")
                print(f"       Encrypted: {c}")
            print(f"  Total Encrypted: {s['TotalEncrypted']}")
            print(f"  Total Decrypted: {s['TotalDecrypted']:.2f}")
        print()
        if self.signature:
            print("Digital Signature exists → Verification:",
                  rsa_verify(self.rsa_keys,
                             json.dumps(self.summary,sort_keys=True).encode(),
                             self.signature))

    def sign_summary(self):
        data=json.dumps(self.summary,sort_keys=True).encode()
        self.signature=rsa_sign(self.rsa_keys,data)
        print("Transaction summary signed successfully.")

    def verify_signature(self):
        if not self.signature:
            print("No signature found.")
            return
        ok=rsa_verify(self.rsa_keys,
                      json.dumps(self.summary,sort_keys=True).encode(),
                      self.signature)
        print("Signature verification result:",ok)

# ===================== Menu Loop =====================
def main():
    sys=SellerSystem()
    while True:
        print("""
======== PAYMENT GATEWAY MENU ========
1. Add Seller
2. Add Transaction
3. Encrypt + Compute Totals
4. Display Summary
5. Sign Summary (RSA)
6. Verify Signature
7. Exit
""")
        ch=input("Enter choice: ").strip()
        if ch=="1": sys.add_seller()
        elif ch=="2": sys.add_transaction()
        elif ch=="3": sys.encrypt_transactions()
        elif ch=="4": sys.show_summary()
        elif ch=="5": sys.sign_summary()
        elif ch=="6": sys.verify_signature()
        elif ch=="7": break
        else: print("Invalid choice!")

if __name__=="__main__":
    main()
