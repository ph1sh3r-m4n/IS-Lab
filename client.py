import socket, json, secrets, math

# ---------- Paillier Encryption ----------
def paillier_encrypt(m, n, g):
    n2 = n * n
    r = secrets.randbelow(n - 1) + 1
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

# ---------- Seller Client ----------
def connect_to_server(name, transactions, host="127.0.0.1", port=5000):
    s = socket.socket()
    s.connect((host, port))

    # Receive public key from server
    data = json.loads(s.recv(8192).decode())
    n, g = data["pubkey"]
    print(f"[CLIENT] Connected to server. Got Paillier key (n={n})")

    # Encrypt each transaction
    encrypted_transactions = []
    for amt in transactions:
        paisa = int(round(amt * 100))
        c = paillier_encrypt(paisa, n, g)
        encrypted_transactions.append(c)

    # Send encrypted data
    send_data = {
        "seller": name,
        "transactions": encrypted_transactions
    }
    s.send(json.dumps(send_data).encode())
    msg = s.recv(4096).decode()
    print("[SERVER REPLY]:", msg)
    s.close()

# ---------- Menu ----------
def main():
    name = input("Enter Seller Name: ")
    transactions = []

    while True:
        print(f"""
======== SELLER MENU ({name}) ========
1. Add Transaction
2. Send to Payment Gateway
3. Exit
""")
        ch = input("Enter choice: ")

        if ch == "1":
            amt = float(input("Enter amount (INR): "))
            transactions.append(amt)

        elif ch == "2":
            if not transactions:
                print("No transactions to send.")
            else:
                connect_to_server(name, transactions)

        elif ch == "3":
            print("Exiting client.")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
