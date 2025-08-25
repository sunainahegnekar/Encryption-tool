import hashlib

def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()

def hash_file(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# For testing
if __name__ == "__main__":
    msg = input("Enter message to hash: ")
    print("SHA-256 Hash:", hash_message(msg))
