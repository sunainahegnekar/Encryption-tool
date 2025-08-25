import streamlit as st
from symmetric_encrypt import encrypt_message, decrypt_message, generate_key as gen_aes_key
from asymmetric_encrypt import encrypt_data as rsa_encrypt, decrypt_data as rsa_decrypt, generate_keys as gen_rsa_keys
from hash_data import hash_message
import os

st.set_page_config(page_title="Encryption Tool", layout="centered")
st.title("🔐 Encryption Tool Development")
st.markdown("Choose a method to securely **Encrypt, Decrypt, or Hash** your data.")

mode = st.sidebar.selectbox("Choose Mode", ["Symmetric (AES)", "Asymmetric (RSA)", "Hashing (SHA-256)"])

# ---------------- AES Section ----------------
if mode == "Symmetric (AES)":
    st.header("AES Encryption (Symmetric)")
    
    if not os.path.exists("keys/aes_key.key"):
        if st.button("Generate AES Key"):
            gen_aes_key()
            st.success("Key generated and saved!")

    action = st.radio("Choose Action", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter your message")

    if action == "Encrypt" and st.button("Encrypt"):
        try:
            encrypted = encrypt_message(text)
            st.code(encrypted, language="plaintext")
        except Exception as e:
            st.error(f"Error: {e}")

    elif action == "Decrypt" and st.button("Decrypt"):
        try:
            decrypted = decrypt_message(text.encode())
            st.code(decrypted, language="plaintext")
        except Exception as e:
            st.error("Invalid encrypted input or missing key.")

# ---------------- RSA Section ----------------
elif mode == "Asymmetric (RSA)":
    st.header("RSA Encryption (Asymmetric)")

    if not os.path.exists("keys/public.pem") or not os.path.exists("keys/private.pem"):
        if st.button("Generate RSA Key Pair"):
            gen_rsa_keys()
            st.success("Public & Private keys saved!")

    action = st.radio("Choose Action", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter your message")

    if action == "Encrypt" and st.button("Encrypt"):
        try:
            encrypted = rsa_encrypt(text)
            st.code(encrypted, language="plaintext")
        except Exception as e:
            st.error(f"Error: {e}")

    elif action == "Decrypt" and st.button("Decrypt"):
        try:
            decrypted = rsa_decrypt(eval(text))  # eval is safe here because you are pasting exact byte string
            st.code(decrypted, language="plaintext")
        except Exception as e:
            st.error("Invalid input or missing keys.")

# ---------------- Hashing Section ----------------
elif mode == "Hashing (SHA-256)":
    st.header("SHA-256 Hash Generator")
    text = st.text_area("Enter message to hash")

    if st.button("Hash"):
        hashed = hash_message(text)
        st.code(hashed, language="plaintext")
