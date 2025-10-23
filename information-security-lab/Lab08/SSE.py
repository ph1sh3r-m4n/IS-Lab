# SSE Lab Exercise - AES-based
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

def tokenize(text):
    import re
    return re.findall(r"[a-zA-Z0-9]+", text.lower())

# -------------------- AES Encryption --------------------
aes_key = hashlib.sha256(b"lab-demo-aes-key").digest()[:16]  # 16 bytes key

def aes_encrypt_det(plaintext_bytes):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext_bytes, AES.block_size))

def aes_decrypt_det(cipher_bytes):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(cipher_bytes), AES.block_size)

# -------------------- Build Inverted Index --------------------
inverted_index = {}
for doc_id, doc in enumerate(corpus):
    for token in set(tokenize(doc)):
        inverted_index.setdefault(token, []).append(doc_id)

# -------------------- Encrypt Inverted Index --------------------
def sse_token_encrypt(token):
    return aes_encrypt_det(token.encode('utf-8'))

def sse_postings_encrypt(postings):
    b = ",".join(str(x) for x in postings).encode('utf-8')
    return aes_encrypt_det(b)

def sse_postings_decrypt(ct):
    pt = aes_decrypt_det(ct)
    return [int(x) for x in pt.decode('utf-8').split(",")]

sse_index = {}
for token, postings in inverted_index.items():
    token_ct = sse_token_encrypt(token).hex()
    sse_index[token_ct] = sse_postings_encrypt(postings)

# -------------------- SSE Search --------------------
def sse_search(query):
    qct = sse_token_encrypt(query).hex()
    if qct in sse_index:
        postings = sse_postings_decrypt(sse_index[qct])
        docs = [corpus[i] for i in postings]
        return postings, docs
    else:
        return [], []

# Example Search
query = "encryption"
postings, docs = sse_search(query)
print(f"SSE Search for '{query}' -> docIDs: {postings}")
for d in docs: print("-", d)
