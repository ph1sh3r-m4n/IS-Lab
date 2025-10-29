import socket, json, secrets, math

# ---------- Paillier Encryption ----------
class PaillierClient:
    def __init__(self, n, g):
        self.n = n
        self.n2 = n*n
        self.g = g

    def encrypt(self, m):
        r = secrets.randbelow(self.n-1)+1
        return (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2

# ---------- Client ----------
class SellerClient:
    def __init__(self, name):
        self.name = name
        self.transactions = []
        self.pubkey = None

    def connect(self, host="127.0.0.1", port=5000):
        s = socket.socket()
        s.connect((host, port))
        data = json.loads(s.recv(8192).decode())
        n,g = data["pubkey"]
        self.pubkey = PaillierClient(n,g)
        print(f"[CLIENT] Connected to server. Got Paillier key (n={n})")

        for i, amt in enumerate(self.transactions):
            paisa = int(round(amt*100))
            c = self.pubkey.encrypt(paisa)
            self.transactions[i] = c

        send_data = {
            "seller": self.name,
            "transactions": self.transactions
        }
        s.send(json.dumps(send_data).encode())
        msg = s.recv(4096).decode()
        print("[SERVER REPLY]:", msg)
        s.close()

# ---------- Menu ----------
def main():
    name = input("Enter Seller Name: ")
    client = SellerClient(name)

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
            client.transactions.append(amt)
        elif ch == "2":
            client.connect()
        elif ch == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
