# -----------------------------
# IMPORTS
# -----------------------------
from Crypto.Cipher import AES               # For AES encryption/decryption
from Crypto.Util.Padding import pad, unpad # For padding plaintext to AES block size
from Crypto.PublicKey import RSA           # For RSA key generation
from Crypto.Signature import pkcs1_15      # For signing and verifying with RSA
from Crypto.Hash import SHA512              # For hashing messages with SHA512
from datetime import datetime               # For timestamps
import binascii                             # For converting bytes to hex

# -----------------------------
# AES CONFIGURATION
# -----------------------------
AES_KEY = b'ThisIsA16ByteKey'  # 16 bytes = 128-bit AES key
AES_BLOCK_SIZE = 16             # AES block size

# -----------------------------
# RSA CONFIGURATION
# -----------------------------
rsa_key = RSA.generate(2048)    # Generate a 2048-bit RSA key pair
rsa_public_key = rsa_key.publickey()  # Public key for signing/verification
rsa_private_key = rsa_key             # Private key for signing/verification

# -----------------------------
# DATABASE (in-memory)
# -----------------------------
# Structure: { patient_name: [ (timestamp, encrypted_record, signature) ] }
patients_db = {}

# -----------------------------
# FUNCTION: AES ENCRYPTION
# -----------------------------
def aes_encrypt(plaintext):
    """
    Encrypts the plaintext using AES-128 in CBC mode.
    """
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=b'\x00'*AES_BLOCK_SIZE)  # Fixed IV for simplicity
    padded = pad(plaintext.encode('utf-8'), AES_BLOCK_SIZE)              # Pad to block size
    encrypted = cipher.encrypt(padded)                                   # Encrypt
    return encrypted

# -----------------------------
# FUNCTION: AES DECRYPTION
# -----------------------------
def aes_decrypt(ciphertext):
    """
    Decrypts AES-128 ciphertext using CBC mode.
    """
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=b'\x00'*AES_BLOCK_SIZE)
    decrypted = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)       # Decrypt and unpad
    return decrypted.decode('utf-8')                                     # Convert to string

# -----------------------------
# FUNCTION: SIGN WITH RSA
# -----------------------------
def rsa_sign(data):
    """
    Signs the SHA512 hash of the input data using RSA private key.
    """
    hash_obj = SHA512.new(data.encode('utf-8'))  # Hash the plaintext
    signature = pkcs1_15.new(rsa_private_key).sign(hash_obj)  # Sign the hash
    return signature

# -----------------------------
# FUNCTION: VERIFY SIGNATURE
# -----------------------------
def rsa_verify(data, signature):
    """
    Verifies the RSA signature of the input data.
    Returns True if valid, False otherwise.
    """
    hash_obj = SHA512.new(data.encode('utf-8'))  # Hash the plaintext
    try:
        pkcs1_15.new(rsa_public_key).verify(hash_obj, signature)  # Verify signature
        return True
    except (ValueError, TypeError):
        return False

# -----------------------------
# PATIENT MENU
# -----------------------------
def patient_menu():
    name = input("Enter your name: ")
    while True:
        print("\nPatient Menu:")
        print("1. Upload Medical Record")
        print("2. View Past Records")
        print("3. Back")
        choice = input("Choice: ")

        if choice == '1':
            # Patient uploads a new record
            record = input("Enter your medical record: ")
            encrypted = aes_encrypt(record)         # Encrypt the record using AES
            signature = rsa_sign(record)            # Sign the SHA512 hash of record using RSA
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Timestamp

            # Add record to database
            if name not in patients_db:
                patients_db[name] = []
            patients_db[name].append((timestamp, encrypted, signature))
            print("Record uploaded and signed successfully!")

        elif choice == '2':
            # View past encrypted records
            if name in patients_db:
                for t, enc, sig in patients_db[name]:
                    print(f"\nTimestamp: {t}")
                    print(f"Encrypted Record: {binascii.hexlify(enc).decode()}")
                    print(f"Signature: {binascii.hexlify(sig).decode()}")
            else:
                print("No records found.")

        elif choice == '3':
            break
        else:
            print("Invalid choice!")

# -----------------------------
# DOCTOR MENU
# -----------------------------
def doctor_menu():
    while True:
        print("\nDoctor Menu:")
        print("1. Decrypt Patient Record")
        print("2. Verify Signature")
        print("3. Back")
        choice = input("Choice: ")

        if choice == '1':
            # Decrypt patient record
            patient_name = input("Enter patient name: ")
            if patient_name in patients_db:
                for i, (t, enc, sig) in enumerate(patients_db[patient_name], start=1):
                    print(f"{i}. Timestamp: {t} | Encrypted: {binascii.hexlify(enc).decode()}")
                rec_choice = int(input("Choose record number to decrypt: ")) - 1
                if 0 <= rec_choice < len(patients_db[patient_name]):
                    _, enc, _ = patients_db[patient_name][rec_choice]
                    decrypted = aes_decrypt(enc)
                    print(f"Decrypted Record: {decrypted}")
                else:
                    print("Invalid choice.")
            else:
                print("No records found for this patient.")

        elif choice == '2':
            # Verify signature
            patient_name = input("Enter patient name: ")
            if patient_name in patients_db:
                for i, (t, enc, sig) in enumerate(patients_db[patient_name], start=1):
                    print(f"{i}. Timestamp: {t} | Signature: {binascii.hexlify(sig).decode()}")
                rec_choice = int(input("Choose record number to verify: ")) - 1
                if 0 <= rec_choice < len(patients_db[patient_name]):
                    _, _, sig = patients_db[patient_name][rec_choice]
                    decrypted = aes_decrypt(patients_db[patient_name][rec_choice][1])
                    verified = rsa_verify(decrypted, sig)
                    print(f"Signature Verified: {verified}")
                else:
                    print("Invalid choice.")
            else:
                print("No records found for this patient.")

        elif choice == '3':
            break
        else:
            print("Invalid choice!")

# -----------------------------
# AUDITOR MENU
# -----------------------------
def auditor_menu():
    while True:
        print("\nAuditor Menu:")
        print("1. View Encrypted Records")
        print("2. Verify Signatures")
        print("3. Back")
        choice = input("Choice: ")

        if choice == '1':
            patient_name = input("Enter patient name: ")
            if patient_name in patients_db:
                for t, enc, sig in patients_db[patient_name]:
                    print(f"\nTimestamp: {t}")
                    print(f"Encrypted Record: {binascii.hexlify(enc).decode()}")
            else:
                print("No records found.")

        elif choice == '2':
            patient_name = input("Enter patient name: ")
            if patient_name in patients_db:
                for t, enc, sig in patients_db[patient_name]:
                    decrypted = aes_decrypt(enc)  # Only for verification, auditor cannot see plaintext normally
                    verified = rsa_verify(decrypted, sig)
                    print(f"\nTimestamp: {t} | Signature Verified: {verified}")
            else:
                print("No records found.")

        elif choice == '3':
            break
        else:
            print("Invalid choice!")

# -----------------------------
# MAIN MENU
# -----------------------------
def main():
    while True:
        print("\nHospital Management System")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        role = input("Select role: ")

        if role == '1':
            patient_menu()
        elif role == '2':
            doctor_menu()
        elif role == '3':
            auditor_menu()
        elif role == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice!")

# Run the program
if _name_ == "_main_":
    main()
