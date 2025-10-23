# PKSE Lab Exercise - Paillier-based
import random, hashlib, math
from dataclasses import dataclass

# -------------------- Dataset --------------------
corpus = [
    "security and privacy in cloud computing",
    "searchable encryption techniques for secure search",
    "homomorphic encryption supports computation on encrypted data",
    "symmetric key encryption like aes is fast",
    "asymmetric encryption includes rsa and paillier",
    "secure k v stores and inverted index concepts",
    "document retrieval and information retrieval systems",
    "index construction and inverted lists for search",
    "cryptography protocols include key exchange and signatures",
    "data security, integrity, and confidentiality practices"
]

# -------------------- Tokenize & Build Inverted Index --------------------
def tokenize(text):
    import re
    return re.findall(r"[a-zA-Z0-9]+", text.lower())

inverted_index = {}
for doc_id, doc in enumerate(corpus):
    for token in set(tokenize(doc)):
        inverted_index.setdefault(token, []).append(doc_id)

# -------------------- Paillier Keygen --------------------
def lcm(a, b): return a * b // math.gcd(a, b)

def is_probable_prime(n, k=10):
    if n < 2: return False
    d, s = n-1, 0
    while d % 2 == 0: d//=2; s+=1
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a,d,n)
        if x==1 or x==n-1: continue
        for _ in range(s-1):
            x = pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1<<(bits-1)) | 1
        if is_probable_prime(p): return p

@dataclass
class PaillierPrivateKey: p:int; q:int; n:int; nsq:int; lam:int; mu:int
@dataclass
class PaillierPublicKey: n:int; nsq:int; g:int

def paillier_keygen(bits=256):
    p, q = generate_prime(bits//2), generate_prime(bits//2)
    n = p*q; nsq = n*n; g = n+1
    lam = lcm(p-1,q-1)
    mu = pow((pow(g,lam,nsq)-1)//n, -1, n)
    return PaillierPublicKey(n, nsq, g), PaillierPrivateKey(p,q,n,nsq,lam,mu)

def paillier_encrypt(pub, m):
    r = random.randrange(1,pub.n)
    while math.gcd(r,pub.n)!=1: r=random.randrange(1,pub.n)
    return (pow(pub.g,m,pub.nsq)*pow(r,pub.n,pub.nsq)) % pub.nsq

def paillier_decrypt(priv, c):
    L = (pow(c,priv.lam,priv.nsq)-1)//priv.n
    return (L*priv.mu)%priv.n

# -------------------- Generate Keys --------------------
pub, priv = paillier_keygen(bits=256)

# -------------------- Build Encrypted Index --------------------
def token_trapdoor(token):
    return hashlib.sha256(token.encode()).hexdigest()

pkse_index = {}
for token, postings in inverted_index.items():
    trap = token_trapdoor(token)
    pkse_index[trap] = [paillier_encrypt(pub, pid) for pid in postings]

# -------------------- PKSE Search --------------------
def pkse_search(query):
    trap = token_trapdoor(query)
    enc_postings = pkse_index.get(trap, [])
    dec_postings = [paillier_decrypt(priv,c) for c in enc_postings]
    docs = [corpus[i] for i in dec_postings]
    return dec_postings, docs

# -------------------- Example Search --------------------
query2 = "data"
postings2, docs2 = pkse_search(query2)
print(f"\nPKSE Search for '{query2}' -> docIDs: {postings2}")
for d in docs2:
    print("-", d)
