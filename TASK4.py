import os
import sys

# Ensure required modules are installed
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print("[!] Error: 'pycryptodome' module is not installed. Install it using: pip install pycryptodome")
    sys.exit(1)

import hashlib

# Check if Tkinter is available before importing
tkinter_available = True
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError:
    tkinter_available = False
    print("Warning: Tkinter module is not available. Running in CLI mode.")

# AES Key Derivation Function
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

# Encrypt File
def encrypt_file(file_path, password):
    try:
        salt = os.urandom(16)
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_GCM)
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)
        
        print(f"Success: File encrypted: {encrypted_file_path}")
    except Exception as e:
        print(f"Error: {e}")

# Decrypt File
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        decrypted_file_path = file_path.replace(".enc", "_decrypted")
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"Success: File decrypted: {decrypted_file_path}")
    except Exception as e:
        print(f"Error: {e}")

# CLI Mode
def cli_mode():
    while True:
        print("\nOptions:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        
        try:
            choice = input("Enter your choice: ").strip()
        except OSError:
            print("I/O error detected. Exiting...")
            break
        
        if choice == "1":
            file_path = input("Enter the file path to encrypt: ").strip()
            password = input("Enter the encryption password: ").strip()
            encrypt_file(file_path, password)
        elif choice == "2":
            file_path = input("Enter the file path to decrypt: ").strip()
            password = input("Enter the decryption password: ").strip()
            decrypt_file(file_path, password)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    cli_mode()
