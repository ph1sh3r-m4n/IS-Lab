`auditor_server.py (server — auditor)`
```python
# auditor_server.py
"""
Auditor (server)
Listens for a single doctor's upload, stores the encrypted data and
Paillier public key & ElGamal public key & MD5 signature.
Provides a menu:
 1) Search for keyword (without decrypting file)
 2) Add budgets homomorphically (returns encrypted sum)
 3) Verify ElGamal signature (on MD5)
"""

import socket
import json
import base64
import hashlib
from math import gcd

HOST = '127.0.0.1'
PORT = 65432

# --- utility functions for converting big ints to strings for JSON ---
def int_to_b64(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    return base64.b64encode(b).decode()

def b64_to_int(s: str) -> int:
    b = base64.b64decode(s.encode())
    return int.from_bytes(b, 'big')

# Simple Paillier homomorphic operations (we'll only need ciphertext multiply)
def mod_pow(a, e, m): return pow(a, e, m)

def handle_menu(data):
    """
    data is a dict from the client with keys:
      - 'rsa_encrypted_lines': list of str (b64 ints)
      - 'token_map': dict token -> list of line_numbers
      - 'paillier_pub': { 'n': str(b64), 'g': str(b64) }
      - 'encrypted_budgets': dict line_number -> list of ciphertexts (as b64 strings)
      - 'md5': hex string
      - 'elgamal_pub': { 'p': b64, 'g': b64, 'y': b64 }
      - 'elgamal_sig': { 'r': b64, 's': b64 }
    """
    rsa_lines = data['rsa_encrypted_lines']
    token_map = data['token_map']
    paillier_pub = data['paillier_pub']
    enc_budgets = data['encrypted_budgets']
    md5_hex = data['md5']
    elg_pub = data['elgamal_pub']
    elg_sig = data['elgamal_sig']

    n = b64_to_int(paillier_pub['n'])
    g = b64_to_int(paillier_pub['g'])
    n_sq = n * n

    p_elg = b64_to_int(elg_pub['p'])
    g_elg = b64_to_int(elg_pub['g'])
    y_elg = b64_to_int(elg_pub['y'])
    r = b64_to_int(elg_sig['r'])
    s = b64_to_int(elg_sig['s'])

    def search_keyword():
        kw = input("Enter keyword to search (case-insensitive): ").strip().lower()
        token = hashlib.sha256(kw.encode()).hexdigest()
        hits = token_map.get(token, [])
        if not hits:
            print("No matches (search done on tokens only — lines remain encrypted).")
        else:
            print(f"Found matches at line numbers: {hits}")
            print("Corresponding encrypted lines (RSA ciphertexts):")
            for ln in hits:
                idx = ln
                if idx < len(rsa_lines):
                    print(f" line {ln}: {rsa_lines[idx]}")
                else:
                    print(f" line {ln}: (not available)")
        input("Press enter to continue...")

    def add_budgets():
        # Sum all encrypted budgets across the file homomorphically.
        # Each budget is a Paillier ciphertext c. Homomorphic sum = product of c's mod n^2
        all_cts = []
        for ln, clist in enc_budgets.items():
            for c_b64 in clist:
                all_cts.append(b64_to_int(c_b64))
        if not all_cts:
            print("No budgets found.")
            return
        prod = 1
        for c in all_cts:
            prod = (prod * c) % n_sq
        # Return encrypted sum to client (b64)
        prod_b64 = int_to_b64(prod)
        print("Encrypted sum (Paillier) computed. This is the ciphertext of the sum.")
        print("Send this ciphertext back to doctor so they can decrypt (auditor does not have private key).")
        print(prod_b64)
        input("Press enter to continue...")

    def verify_signature():
        # ElGamal signature verification for hash md5_hex.
        # Convert md5 to int
        h = int(md5_hex, 16)
        # verify: 1 < r < p and compute v1 = y^r * r^s mod p, v2 = g^h mod p
        if r <= 0 or r >= p_elg:
            print("Invalid r in signature.")
            return
        v1 = (pow(y_elg, r, p_elg) * pow(r, s, p_elg)) % p_elg
        v2 = pow(g_elg, h, p_elg)
        if v1 == v2:
            print("Signature VALID for provided MD5 hash.")
        else:
            print("Signature INVALID.")
        input("Press enter to continue...")

    while True:
        print("\n=== Auditor Menu ===")
        print("1) Search keyword (without decrypting)")
        print("2) Add budgets (homomorphic; returns encrypted sum)")
        print("3) Verify signature (ElGamal on MD5)")
        print("4) Exit")
        ch = input("Choice: ").strip()
        if ch == '1':
            search_keyword()
        elif ch == '2':
            add_budgets()
        elif ch == '3':
            verify_signature()
        elif ch == '4':
            print("Exiting auditor menu.")
            break
        else:
            print("Invalid choice.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Auditor listening on {HOST}:{PORT} ... (waiting for doctor upload)")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            # read length-prefixed JSON
            length_bytes = conn.recv(8)
            if not length_bytes:
                print("No data.")
                return
            total_len = int.from_bytes(length_bytes, 'big')
            received = b''
            while len(received) < total_len:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received += chunk
            payload = json.loads(received.decode())
            print("Received upload from doctor.")
            handle_menu(payload)

if __name__ == '__main__':
    start_server()

```
`doctor_client.py (client — doctor)`
```python
# doctor_client.py
"""
Doctor (client)
Usage: python doctor_client.py sample_input.txt
The file should be plain text. The script:
 - reads the file
 - generates RSA, ElGamal, Paillier keys (small, demo only)
 - encrypts each line with RSA (as ints -> base64)
 - computes MD5 of full plaintext and signs it with ElGamal
 - extracts integer budgets (regex) and Paillier-encrypts them
 - builds token map: token=sha256(lowercase_word) -> list of line indices
 - sends a JSON message to auditor with all the public data & ciphertexts
"""

import sys, socket, json, base64, re, hashlib, random
from math import gcd
from secrets import randbelow

HOST = '127.0.0.1'
PORT = 65432

# --- helpers for big-int json encoding ---
def int_to_b64(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    return base64.b64encode(b).decode()

def b64_to_int(s: str) -> int:
    b = base64.b64decode(s.encode())
    return int.from_bytes(b, 'big')

# --- RSA (textbook educational) ---
def is_prime(n):
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Miller-Rabin with a few bases (sufficient for small demo)
    d = n-1
    s = 0
    while d % 2 == 0:
        d//=2; s+=1
    def try_a(a):
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            return True
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                return True
        return False
    for a in [2,3,5,7]:
        if a >= n: break
        if not try_a(a):
            return False
    return True

def gen_prime(start=100, end=500):
    while True:
        p = random.randrange(start, end)
        if is_prime(p):
            return p

def rsa_keygen():
    p = gen_prime(200, 800)
    q = gen_prime(200, 800)
    while q == p:
        q = gen_prime(200, 800)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    # compute d
    def egcd(a,b):
        if b==0: return (1,0,a)
        x,y,g = egcd(b, a%b)
        return (y, x - (a//b)*y, g)
    x,y,g = egcd(e, phi)
    d = x % phi
    return {'n': n, 'e': e, 'd': d}

def rsa_encrypt_int(m_int, pub):
    return pow(m_int, pub['e'], pub['n'])

def rsa_encrypt_bytes(b, pub):
    m_int = int.from_bytes(b, 'big')
    if m_int >= pub['n']:
        # naive chunking (split in half)
        mid = len(b)//2 or 1
        hi = rsa_encrypt_bytes(b[:mid], pub)
        lo = rsa_encrypt_bytes(b[mid:], pub)
        return (hi, lo)
    return rsa_encrypt_int(m_int, pub)

# --- Simple ElGamal signature (on mod p) ---
def elgamal_keygen():
    # small safe-ish prime p
    p = gen_prime(500, 2000)
    # find generator g (very naive)
    g = 2
    while pow(g, (p-1)//2, p) == 1:
        g += 1
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_sign(m_int, key):
    p = key['p']
    g = key['g']
    x = key['x']
    while True:
        k = random.randrange(2, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p-1)
    s = (k_inv * (m_int - x * r)) % (p-1)
    return (r, s)

# --- Paillier (for additive homomorphism) ---
def paillier_keygen():
    # tiny primes for demo
    p = gen_prime(50, 200)
    q = gen_prime(50, 200)
    while q == p:
        q = gen_prime(50, 200)
    n = p*q
    g = n + 1
    # lambda = lcm(p-1, q-1)
    def lcm(a,b): return a*b//gcd(a,b)
    lam = lcm(p-1, q-1)
    # mu = (L(g^lambda mod n^2))^{-1} mod n
    n_sq = n*n
    x = pow(g, lam, n_sq)
    L = (x - 1) // n
    mu = pow(L, -1, n)
    return {'n': n, 'g': g, 'lambda': lam, 'mu': mu}

def paillier_encrypt(m, pub):
    n = pub['n']
    n_sq = n*n
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            break
    c = (pow(pub['g'], m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def paillier_decrypt(c, priv):
    n = priv['n']
    n_sq = n*n
    x = pow(c, priv['lambda'], n_sq)
    L = (x - 1) // n
    m = (L * priv['mu']) % n
    return m

# --- parsing and building structures ---
def extract_budgets_and_token_map(lines):
    budget_re = re.compile(r'\b(\d{1,9})\b')  # naive: any integer up to 9 digits
    encrypted_budgets = {}  # will be filled later with paillier ciphers
    token_map = {}
    for idx, line in enumerate(lines):
        # budgets:
        nums = budget_re.findall(line)
        # tokens
        words = re.findall(r"[A-Za-z0-9]+", line.lower())
        for w in set(words):
            token = hashlib.sha256(w.encode()).hexdigest()
            token_map.setdefault(token, []).append(idx)
        # store budgets as ints for later encryption
        if nums:
            encrypted_budgets[idx] = [int(n) for n in nums]
    return encrypted_budgets, token_map

def prepare_payload(filename):
    # read file
    with open(filename, 'rb') as f:
        raw = f.read()
    text = raw.decode(errors='ignore')
    lines = text.splitlines()

    # RSA keys + encrypt lines (we'll encrypt each line as bytes -> int -> ciphertext)
    rsa = rsa_keygen()
    rsa_pub = {'n': rsa['n'], 'e': rsa['e']}
    rsa_encrypted_lines = []
    for line in lines:
        b = line.encode()
        c = rsa_encrypt_bytes(b, rsa_pub)
        # for simplicity, if we got a tuple due to chunking, convert both to base64
        if isinstance(c, tuple):
            hi_b64 = int_to_b64(c[0])
            lo_b64 = int_to_b64(c[1])
            rsa_encrypted_lines.append(json.dumps({'chunked': True, 'hi': hi_b64, 'lo': lo_b64}))
        else:
            rsa_encrypted_lines.append(json.dumps({'chunked': False, 'c': int_to_b64(c)}))

    # MD5 hash of full plaintext
    md5 = hashlib.md5(raw).hexdigest()

    # ElGamal sign the md5 (convert hex to int)
    elg = elgamal_keygen()
    h_int = int(md5, 16)
    r, s = elgamal_sign(h_int, elg)

    # Paillier keys and encryption of budgets
    paillier = paillier_keygen()

    # Extract budgets and token map
    budgets_int_map, token_map = extract_budgets_and_token_map(lines)
    encrypted_budgets = {}
    for ln, ints in budgets_int_map.items():
        encrypted_budgets[ln] = []
        for m in ints:
            c = paillier_encrypt(m % paillier['n'], paillier)  # encrypt m mod n
            encrypted_budgets[ln].append(int_to_b64(c))

    # Build JSON-able payload
    payload = {
        'rsa_encrypted_lines': rsa_encrypted_lines,
        'token_map': token_map,  # token->list of line numbers
        'paillier_pub': {'n': int_to_b64(paillier['n']), 'g': int_to_b64(paillier['g'])},
        'encrypted_budgets': {str(k): v for k, v in encrypted_budgets.items()},
        'md5': md5,
        'elgamal_pub': {'p': int_to_b64(elg['p']), 'g': int_to_b64(elg['g']), 'y': int_to_b64(elg['y'])},
        'elgamal_sig': {'r': int_to_b64(r), 's': int_to_b64(s)}
    }

    # Return also private keys locally so the doctor can decrypt sums and also maintain RSA private key
    local_private = {
        'rsa_priv': {'n': rsa['n'], 'd': rsa['d']},
        'paillier_priv': {'n': paillier['n'], 'lambda': paillier['lambda'], 'mu': paillier['mu']},
        'elgamal_priv': {'x': elg['x'], 'p': elg['p'], 'g': elg['g']}
    }
    return payload, local_private

def send_payload(payload):
    # send length-prefixed JSON
    msg = json.dumps(payload).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(len(msg).to_bytes(8, 'big'))
        s.sendall(msg)
    print("Payload sent to auditor.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python doctor_client.py inputfile.txt")
        sys.exit(1)
    filename = sys.argv[1]
    payload, priv = prepare_payload(filename)
    # Save private keys locally for later (doctor decrypts sums)
    with open('doctor_private.json', 'w') as f:
        # store as simple json (ints as ints)
        json.dump({
            'rsa_priv': {k: int(v) for k, v in priv['rsa_priv'].items()},
            'paillier_priv': {k: int(v) for k, v in priv['paillier_priv'].items()},
            'elgamal_priv': {k: int(v) for k, v in priv['elgamal_priv'].items()}
        }, f)
    send_payload(payload)
    print("Doctor private keys saved to doctor_private.json — keep them secret.")
    print("\nNote: Auditor will not be able to decrypt RSA lines nor Paillier sums (only doctor has private keys).")
    print("When auditor does homomorphic addition they will print the encrypted sum; doctor can decrypt it using saved Paillier private key.")

```
`Example sample_input.txt`
```yaml
DrName: Dr. A. K. Chaudhuri
Branch: Cardiology
Date: 2025-10-01 10:00:00
Budget 12000 for patient X
Notes: Provided immediate care.

DrName: Dr. B. Basu
Branch: Neurology
Date: 2025-09-30 09:15:00
Budget 8000 for patient Y
Notes: Observations recorded.

```
Running the demo

Start the auditor:

python auditor_server.py


It waits for the doctor.

In a second terminal, run the doctor:

python doctor_client.py sample_input.txt


This sends the payload and writes doctor_private.json (contains demo private keys).

In the auditor terminal you get a menu. Try:

Option 1: search for budget or neurology (type lowercase or whatever; tokenization is simple).

Option 2: add budgets — it will compute and print the encrypted Paillier ciphertext of the sum. Copy that ciphertext (base64 output).

Option 3: verify signature — it will print Valid/Invalid for the MD5+ElGamal signature.

Decrypting the homomorphic sum (doctor side):

Use doctor_private.json and the ciphertext printed by the auditor. To decrypt, use the Paillier formulas in paillier_decrypt() — I provide that in the client script already (saved as function). For convenience, you can create a tiny script to load the ciphertext and decrypt with stored private key.
