from cryptography.fernet import Fernet
import os

# Step 1: Generate Key and Save
def generate_key():
    key = Fernet.generate_key()
    with open("keys/aes_key.key", "wb") as f:
        f.write(key)
    print("Key generated and saved to 'keys/aes_key.key'")

# Step 2: Load Key
def load_key():
    return open("keys/aes_key.key", "rb").read()

# Step 3: Encrypt Message
def encrypt_message(message):
    key = load_key()
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted

# Step 4: Decrypt Message
def decrypt_message(encrypted_msg):
    key = load_key()
    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted_msg)
    return decrypted.decode()

# For testing
if __name__ == "__main__":
    if not os.path.exists("keys/aes_key.key"):
        generate_key()

    message = input("Enter a message to encrypt: ")
    encrypted = encrypt_message(message)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(encrypted)
    print("Decrypted:", decrypted)
