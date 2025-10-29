```python
#!/usr/bin/env python3
"""
doctor_auditor_system.py

Menu-based client-server demo:
- Doctor encrypts text file (hybrid RSA/AES), hashes with MD5, signs MD5 with ElGamal.
- Budgets extracted and encrypted with Paillier (additively homomorphic).
- Search index: deterministic tokens (SHA256 keyed) map -> encrypted record IDs.
- Auditor can search (without decrypting), homomorphically add budgets, and verify signatures.

This is an educational demo. Not production-ready for real confidential data.
"""

import os
import sys
import json
import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from math import gcd

# -------------------------
# Utility functions
# -------------------------
def md5_of_bytes(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def deterministic_token(secret_key: bytes, keyword: str) -> str:
    # deterministic token = sha256(secret_key || keyword)
    return hashlib.sha256(secret_key + keyword.encode()).hexdigest()

# -------------------------
# Hybrid RSA + AES (for file encryption)
# -------------------------
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem

def hybrid_encrypt_bytes(public_pem: bytes, plaintext: bytes):
    # AES session key
    session_key = get_random_bytes(32)  # AES-256
    # Encrypt plaintext with AES-GCM (we'll use AES-CBC for simplicity)
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(plaintext, AES.block_size))
    iv = cipher_aes.iv
    # Encrypt session key with RSA-OAEP
    rsa_key = RSA.import_key(public_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Return a JSON-like blob fields base64-encoded to be file-storable
    return {
        "enc_session_key": b64encode(enc_session_key).decode(),
        "iv": b64encode(iv).decode(),
        "ciphertext": b64encode(ct_bytes).decode()
    }

def hybrid_decrypt_bytes(private_pem: bytes, blob: dict):
    rsa_key = RSA.import_key(private_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(b64decode(blob["enc_session_key"]))
    iv = b64decode(blob["iv"])
    ct = b64decode(blob["ciphertext"])
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    pt = unpad(cipher_aes.decrypt(ct), AES.block_size)
    return pt

# -------------------------
# ElGamal signature (simple)
# -------------------------
# We implement a straightforward ElGamal signature scheme over integers mod p,
# with hash-to-int = int(sha256(message).hexdigest(), 16).
def generate_elgamal_keypair(bits=1024):
    # generate a safe-ish prime p and generator g (this is illustrative)
    # For simplicity we'll pick a random prime via probable prime test.
    # To keep code short and deterministic-ish, we'll use small-ish primes (not secure).
    from Crypto.Util import number
    p = number.getPrime(bits)
    # find g: pick random 2..p-2
    g = random.randint(2, p-2)
    x = random.randint(1, p-2)  # private
    y = pow(g, x, p)  # public
    return {"p": p, "g": g, "y": y, "x": x}

def elgamal_sign(priv: dict, message: bytes):
    p = priv["p"]; g = priv["g"]; x = priv["x"]
    H = int(hashlib.sha256(message).hexdigest(), 16)
    while True:
        k = random.randint(2, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p-1)
    s = (k_inv * (H - x * r)) % (p - 1)
    return {"r": r, "s": s}

def elgamal_verify(pub: dict, message: bytes, signature: dict):
    p = pub["p"]; g = pub["g"]; y = pub["y"]
    r = signature["r"]; s = signature["s"]
    if not (0 < r < p):
        return False
    H = int(hashlib.sha256(message).hexdigest(), 16)
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, H, p)
    return left == right

# -------------------------
# Simple Paillier implementation (educational)
# -------------------------
# Keygen, encrypt, decrypt, homomorphic add
def lcm(a, b): return a*b // gcd(a,b)

def paillier_keygen(bits=512):
    # generate two primes p, q
    from Crypto.Util import number
    p = number.getPrime(bits//2)
    q = number.getPrime(bits//2)
    n = p * q
    lam = lcm(p-1, q-1)
    # choose g = n+1 (simplification), mu = (L(g^lambda mod n^2))^{-1} mod n
    nsq = n * n
    g = n + 1
    x = pow(g, lam, nsq)
    L = (x - 1) // n
    mu = pow(L, -1, n)
    pub = {"n": n, "g": g}
    priv = {"lam": lam, "mu": mu, "p": p, "q": q}
    return pub, priv

def paillier_encrypt(pub: dict, m: int):
    n = pub["n"]; g = pub["g"]
    nsq = n*n
    # r in [1, n-1] coprime to n
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(pub: dict, priv: dict, c: int):
    n = pub["n"]; nsq = n*n
    lam = priv["lam"]; mu = priv["mu"]
    x = pow(c, lam, nsq)
    L = (x - 1) // n
    m = (L * mu) % n
    return m

def paillier_homomorphic_add(pub: dict, c1: int, c2: int):
    nsq = pub["n"]*pub["n"]
    return (c1 * c2) % nsq

# -------------------------
# Simple searchable index (deterministic tokens)
# -------------------------
# Build mapping token -> list of record_ids (strings)
# Auditor stores token->list (can't see keyword because token is hashed with secret)
# Doctor sends token when searching.

# -------------------------
# Demo storage structures (simulating Auditor DB)
# -------------------------
AUDITOR_DB = {
    "records": {},        # record_id -> encrypted_blob (json)
    "index": {},          # token -> list of record_ids
    "budgets": {},        # record_id -> list of paillier-ciphertexts
    "metadata": {}        # record_id -> metadata such as md5, signature, elgamal_pub etc
}

# -------------------------
# Doctor operations
# -------------------------
def doctor_create_record(file_path: str, rsa_pub_pem: bytes, elgamal_priv: dict, paillier_pub: dict, search_secret: bytes):
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    md5 = md5_of_bytes(data)
    # hybrid encrypt
    enc_blob = hybrid_encrypt_bytes(rsa_pub_pem, data)
    # signature on MD5 using ElGamal (we sign the md5 hex as bytes)
    signature = elgamal_sign(elgamal_priv, md5.encode())
    # parse text for budgets and branch keywords (simple heuristics)
    text = data.decode(errors="ignore")
    # budgets: find numbers prefixed by 'budget:' or 'Budget:' or 'BUDGET:'
    budgets = []
    for line in text.splitlines():
        low = line.lower()
        if "budget" in low:
            # extract digits
            import re
            nums = re.findall(r'[\d]+', line)
            for n in nums:
                budgets.append(int(n))
    # If none found, try to find standalone numbers
    if not budgets:
        import re
        budgets = [int(x) for x in re.findall(r'\b\d+\b', text)]
    if not budgets:
        budgets = [0]
    # Encrypt budgets with Paillier
    enc_budgets = [paillier_encrypt(paillier_pub, b) for b in budgets]
    # Search tokens: find branches - look for words like 'branch:' ... simplified
    tokens = []
    for line in text.splitlines():
        if "branch" in line.lower():
            # extract possible branch name after colon
            parts = line.split(":",1)
            if len(parts) > 1:
                branch = parts[1].strip().split()[0]
                token = deterministic_token(search_secret, branch)
                tokens.append(token)
    # if none, fallback: look for 'department' or 'dept'
    if not tokens:
        for line in text.splitlines():
            if "department" in line.lower() or "dept" in line.lower():
                parts = line.split(":",1)
                if len(parts) > 1:
                    branch = parts[1].strip().split()[0]
                    token = deterministic_token(search_secret, branch)
                    tokens.append(token)
    # fallback: use filename as branch token
    if not tokens:
        fname = os.path.basename(file_path).split(".")[0]
        tokens.append(deterministic_token(search_secret, fname))
    # create record id
    record_id = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    # Prepare stored metadata
    meta = {
        "md5": md5,
        "signature": signature,
        "elgamal_pub": {"p": elgamal_priv["p"], "g": elgamal_priv["g"], "y": elgamal_priv["y"]},
        "original_budgets_count": len(budgets)
    }
    # Send to auditor (store)
    AUDITOR_DB["records"][record_id] = enc_blob
    AUDITOR_DB["metadata"][record_id] = meta
    AUDITOR_DB["budgets"][record_id] = enc_budgets
    # update index
    for t in tokens:
        AUDITOR_DB["index"].setdefault(t, []).append(record_id)
    print(f"[Doctor] Uploaded record id: {record_id}")
    return record_id, tokens

# -------------------------
# Auditor operations
# -------------------------
def auditor_search(token: str):
    # Return list of record IDs matching token (encrypted blobs remain hidden)
    recs = AUDITOR_DB["index"].get(token, [])
    # auditor returns encrypted blobs (but not decrypted)
    results = []
    for rid in recs:
        results.append({
            "record_id": rid,
            "enc_blob": AUDITOR_DB["records"][rid],
            "metadata": {"md5": AUDITOR_DB["metadata"][rid]["md5"],
                         "original_budgets_count": AUDITOR_DB["metadata"][rid]["original_budgets_count"]}
        })
    return results

def auditor_homomorphic_add(record_ids: list, paillier_pub: dict):
    # Returns product of ciphertexts per record (aggregated), assuming each record has a list of budgets;
    # We'll sum budgets per-record to create a per-record ciphertext, then multiply across records.
    nsq = paillier_pub["n"] * paillier_pub["n"]
    aggregated = 1
    for rid in record_ids:
        c_list = AUDITOR_DB["budgets"].get(rid, [])
        # multiply (homomorphic add) ciphers within record to get sum for that record
        c_rec = 1
        for c in c_list:
            c_rec = (c_rec * c) % nsq
        aggregated = (aggregated * c_rec) % nsq
    return aggregated

def auditor_verify_signature(record_id: str):
    meta = AUDITOR_DB["metadata"].get(record_id)
    enc_blob = AUDITOR_DB["records"].get(record_id)
    if not meta or not enc_blob:
        return False, "Record not found"
    md5 = meta["md5"]
    sig = meta["signature"]
    pub = meta["elgamal_pub"]
    ok = elgamal_verify(pub, md5.encode(), sig)
    return ok, "OK" if ok else "INVALID"

# -------------------------
# CLI menu
# -------------------------
def print_menu():
    print("\n=== Doctor <-> Auditor demo menu ===")
    print("1) Generate keys (RSA, ElGamal, Paillier, search_secret)")
    print("2) Doctor: upload a text file (encrypt, hash, sign, index, encrypt budgets)")
    print("3) Auditor: search by branch keyword (doctor must provide token)")
    print("4) Auditor: homomorphically add budgets for record ids")
    print("5) Auditor: verify signature of a record")
    print("6) Doctor: decrypt an encrypted record (requires RSA private)")
    print("7) Exit")

def main_menu():
    state = {}
    while True:
        print_menu()
        choice = input("Choose: ").strip()
        if choice == "1":
            print("Generating RSA key pair (2048)...")
            priv_rsa, pub_rsa = generate_rsa_keypair(2048)
            print("Generating ElGamal keypair (1024 bits)...")
            elg = generate_elgamal_keypair(1024)
            print("Generating Paillier keys (512 bits)...")
            pa_pub, pa_priv = paillier_keygen(512)
            secret = get_random_bytes(16)
            # store in memory
            state.update({
                "rsa_priv": priv_rsa, "rsa_pub": pub_rsa,
                "elg_priv": elg, "elg_pub": {"p": elg["p"], "g": elg["g"], "y": elg["y"]},
                "pa_pub": pa_pub, "pa_priv": pa_priv,
                "search_secret": secret
            })
            print("[Done] Keys and search secret generated and stored in local session.")
        elif choice == "2":
            if "rsa_pub" not in state:
                print("Generate keys first (option 1).")
                continue
            path = input("Path to text file: ").strip()
            try:
                rec_id, tokens = doctor_create_record(path, state["rsa_pub"], state["elg_priv"], state["pa_pub"], state["search_secret"])
                print("Record stored with id:", rec_id)
                print("Search tokens created (doctor should keep these secret):")
                for t in tokens:
                    print("  token:", t)
            except Exception as e:
                print("Error:", e)
        elif choice == "3":
            token = input("Enter deterministic token (doctor-provided): ").strip()
            results = auditor_search(token)
            if not results:
                print("No records found.")
            else:
                print(f"Found {len(results)} records (returned encrypted blobs and metadata):")
                for r in results:
                    print(" - record_id:", r["record_id"], "md5:", r["metadata"]["md5"],
                          "budgets_count:", r["metadata"]["original_budgets_count"])
        elif choice == "4":
            if "pa_pub" not in state:
                print("Need Paillier keys first (option 1).")
                continue
            ids = input("Enter record ids (comma separated) to sum budgets: ").strip().split(",")
            ids = [x.strip() for x in ids if x.strip()]
            if not ids:
                print("No ids given.")
                continue
            csum = auditor_homomorphic_add(ids, state["pa_pub"])
            print("Auditor computed homomorphic ciphertext of sum. (Auditor did not decrypt.)")
            # give ciphertext to doctor to decrypt:
            print("Ciphertext (base64-like int):", csum)
            if "pa_priv" in state:
                total = paillier_decrypt(state["pa_pub"], state["pa_priv"], csum)
                print("Doctor can decrypt the sum; decrypted sum =", total)
            else:
                print("Doctor needs Paillier private key to decrypt the sum.")
        elif choice == "5":
            rid = input("Enter record id to verify: ").strip()
            ok, msg = auditor_verify_signature(rid)
            print("Verification result:", ok, msg)
        elif choice == "6":
            if "rsa_priv" not in state:
                print("Need RSA keys (option 1).")
                continue
            rid = input("Enter record id to decrypt: ").strip()
            blob = AUDITOR_DB["records"].get(rid)
            if not blob:
                print("Record not found.")
                continue
            try:
                pt = hybrid_decrypt_bytes(state["rsa_priv"], blob)
                print("Decrypted plaintext (first 1000 bytes):\n")
                print(pt.decode(errors="ignore")[:1000])
            except Exception as e:
                print("Decryption error:", e)
        elif choice == "7":
            print("Bye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main_menu()

```

My good Nega Bangali — here's a complete, runnable Python program that implements the menu-driven client-server flow you asked for:

Doctor (client) side:

Takes a text file (plain .txt).

Produces an AES-hybrid RSA encryption of the file (RSA encrypts AES key).

Computes MD5 hash of the file.

Signs the MD5 using ElGamal signature (implemented in the script).

Extracts budgets (numbers) from the file and encrypts them with Paillier (additively homomorphic) so the auditor can add budgets without decrypting.

Builds a simple deterministic searchable index (tokenized by branch keywords) so the auditor can search without learning plaintext. (Uses HMAC-like deterministic SHA256 tokens.)

Auditor (server) side:

Stores the encrypted file blobs, search-index mapping (deterministic tokens → record IDs), Paillier ciphertexts for budgets.

Implements three functions:

Search doctors (lookup by deterministic token) — returns encrypted records (no decryption).

Add budgets (homomorphically add Paillier ciphertexts) — returns ciphertext of sum (auditor never decrypts).

Verify signature (verifies ElGamal signature using public key).

This is a self-contained single-file script. It uses PyCryptodome for RSA & AES helper cryptography primitives. The Paillier and ElGamal signature implementations are included in pure Python (small, illustrative, not optimized for production). Save as doctor_auditor_system.py and run with Python 3.10+.
