import os
import bcrypt
import json
import shutil
from cryptography.fernet import Fernet

# Directory setup
USER_DATA_FILE = "users.json"
ENCRYPTED_DIR = "encrypted_files"

os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def generate_key():
    return Fernet.generate_key()

def save_user(username, password):
    users = load_users()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {"password": hashed_pw, "key": generate_key().decode()}
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)

def load_users():
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, "r") as f:
        return json.load(f)

def authenticate(username, password):
    users = load_users()
    if username in users and bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
        return users[username]["key"].encode()
    return None

def encrypt_file(username, filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        encrypted_data = fernet.encrypt(file.read())
    filename = os.path.basename(filepath) + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)
    print(f"File encrypted and stored as: {encrypted_path}")

def decrypt_file(username, filename, key):
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    if not os.path.exists(encrypted_path):
        print("File not found.")
        return
    fernet = Fernet(key)
    with open(encrypted_path, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    output_path = filename.replace(".enc", "")
    with open(output_path, "wb") as file:
        file.write(decrypted_data)
    print(f"File decrypted and saved as: {output_path}")

def list_files(username):
    files = [f.replace(username + "_", "") for f in os.listdir(ENCRYPTED_DIR) if f.startswith(username + "_")]
    return files

def delete_file(username, filename):
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
        print("File deleted successfully.")
    else:
        print("File not found.")

def main():
    print("Welcome to Secure File Storage System")
    while True:
        choice = input("[1] Login  [2] Register  [3] Exit: ")
        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            key = authenticate(username, password)
            if key:
                while True:
                    print("\n[1] Encrypt File  [2] View Files  [3] Decrypt File  [4] Delete File  [5] Logout")
                    action = input("Choose: ")
                    if action == "1":
                        filepath = input("Enter file path to encrypt: ")
                        encrypt_file(username, filepath, key)
                    elif action == "2":
                        print("Stored Files:", list_files(username))
                    elif action == "3":
                        filename = input("Enter file to decrypt: ")
                        decrypt_file(username, filename, key)
                    elif action == "4":
                        filename = input("Enter file to delete: ")
                        delete_file(username, filename)
                    elif action == "5":
                        break
            else:
                print("Invalid credentials.")
        elif choice == "2":
            username = input("Choose a username: ")
            password = input("Choose a password: ")
            save_user(username, password)
            print("Registration successful.")
        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
