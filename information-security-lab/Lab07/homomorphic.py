from Crypto.Util import number

# ---------- RSA IMPLEMENTATION ----------
def generate_rsa_keys(bits=512):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e), (n, d)

def rsa_encrypt(pub_key, plaintext):
    n, e = pub_key
    return pow(plaintext, e, n)

def rsa_decrypt(priv_key, ciphertext):
    n, d = priv_key
    return pow(ciphertext, d, n)

# ---------- DEMO ----------
pub_key, priv_key = generate_rsa_keys()

m1, m2 = 7, 3
c1 = rsa_encrypt(pub_key, m1)
c2 = rsa_encrypt(pub_key, m2)
print("\nEncrypted values:")
print("E(7):", c1)
print("E(3):", c2)

# Homomorphic multiplication (E(m1*m2) = E(m1)*E(m2) mod n)
c_prod = (c1 * c2) % pub_key[0]
decrypted_prod = rsa_decrypt(priv_key, c_prod)

print("\nHomomorphic multiplication (Encrypted form):", c_prod)
print("Decrypted product:", decrypted_prod)
print("Expected product:", m1 * m2)
