import os
from file_encryptor import encrypt_file, decrypt_file

def batch_encrypt(folder_path, output_folder):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isfile(full_path):
            encrypted_name = f"{filename}.enc"
            encrypt_file(full_path, os.path.join(output_folder, encrypted_name))
    print(f"All files in '{folder_path}' encrypted into '{output_folder}'")

def batch_decrypt(folder_path, output_folder):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isfile(full_path) and filename.endswith(".enc"):
            original_name = filename[:-4]  # remove .enc
            decrypt_file(full_path, os.path.join(output_folder, original_name))
    print(f"All '.enc' files in '{folder_path}' decrypted into '{output_folder}'")
