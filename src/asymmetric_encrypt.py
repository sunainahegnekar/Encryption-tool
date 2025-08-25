from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# Step 1: Generate RSA keys
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("keys/private.pem", "wb") as f:
        f.write(private_key)
    with open("keys/public.pem", "wb") as f:
        f.write(public_key)

    print("RSA keys generated and saved.")

# Step 2: Encrypt with Public Key
def encrypt_data(data):
    pub_key = RSA.import_key(open("keys/public.pem").read())
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data.encode())

# Step 3: Decrypt with Private Key
def decrypt_data(enc_data):
    priv_key = RSA.import_key(open("keys/private.pem").read())
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(enc_data).decode()

# For testing
if __name__ == "__main__":
    if not os.path.exists("keys/public.pem"):
        generate_keys()

    message = input("Enter message: ")
    enc = encrypt_data(message)
    print("Encrypted:", enc)

    dec = decrypt_data(enc)
    print("Decrypted:", dec)
