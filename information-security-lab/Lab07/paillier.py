from Crypto.Util import number
import random

# ---------- PAILLIER IMPLEMENTATION ----------
def lcm(x, y):
    return x * y // number.GCD(x, y)

def L(u, n):
    return (u - 1) // n

# Key Generation
def generate_paillier_keys(bits=512):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    lam = lcm(p - 1, q - 1)
    g = n + 1
    n_sq = n * n
    mu = pow(L(pow(g, lam, n_sq), n), -1, n)
    return (n, g), (lam, mu)

# Encryption
def paillier_encrypt(pub_key, plaintext):
    n, g = pub_key
    n_sq = n * n
    r = random.randrange(1, n)
    c = (pow(g, plaintext, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# Decryption
def paillier_decrypt(priv_key, pub_key, ciphertext):
    n, g = pub_key
    lam, mu = priv_key
    n_sq = n * n
    x = pow(ciphertext, lam, n_sq)
    m = (L(x, n) * mu) % n
    return m

# ---------- DEMO ----------
pub_key, priv_key = generate_paillier_keys()
print("Public key (n):", pub_key[0])

m1, m2 = 15, 25
c1 = paillier_encrypt(pub_key, m1)
c2 = paillier_encrypt(pub_key, m2)
print("\nEncrypted values:")
print("E(15):", c1)
print("E(25):", c2)

# Homomorphic addition (E(m1+m2) = E(m1)*E(m2) mod n^2)
c_sum = (c1 * c2) % (pub_key[0] ** 2)
decrypted_sum = paillier_decrypt(priv_key, pub_key, c_sum)

print("\nHomomorphic addition (Encrypted form):", c_sum)
print("Decrypted sum:", decrypted_sum)
print("Expected sum:", m1 + m2)
