import os
import re
import bcrypt
import json
import getpass
from cryptography.fernet import Fernet

# Directory setup
USER_DATA_FILE = "users.json"
ENCRYPTED_DIR = "encrypted_files"

os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def generate_key():
    return Fernet.generate_key()

def save_user(username, password):
    users = load_users()
    # hash and salt password
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {"password": hashed_pw, "key": generate_key().decode()}
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent=4)

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

def validate_password(password):
    if (len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+\-=\[\]{};':\\|,.<>\/?]", password)):
        return True
    return False

def encrypt_file(username, filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        encrypted_data = fernet.encrypt(file.read())
    filename = os.path.basename(filepath) + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)
    print(f"\nFile encrypted and stored as: {encrypted_path}")

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
    print(f"\nFile decrypted and saved as: {output_path}")
    print("Decrypted file content:")
    print(decrypted_data.decode(errors='ignore'))

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
    print("Welcome to Secure File Storage System (SSFS)!")
    print("Here you can safely encrypt and decrypt your files using the AES encryption scheme.")
    while True:
        print("Please select an option [1-3]:")
        choice = input("[1] Login  [2] Register  [3] Exit: ")
        if choice == "1":
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            key = authenticate(username, password)
            if key:
                while True:
                    print("\nWelcome to the dashboard. Here you can encrypt files, view encrypted files,")
                    print("decrypt files, and manage your existing files.")
                    print("Please select an option [1-5]:")
                    print("\n[1] Encrypt File  [2] View Files  [3] Decrypt File  [4] Delete File  [5] Logout")
                    action = input("Choose: ")
                    if action == "1":
                        filepath = input("Enter the file path of the file you wish to encrypt: ")
                        encrypt_file(username, filepath, key)
                    elif action == "2":
                        print("\nStored Files:", list_files(username))
                    elif action == "3":
                        filename = input("\nEnter the name of the file to decrypt: ")
                        decrypt_file(username, filename, key)
                    elif action == "4":
                        filename = input("\nEnter the name of the file to delete: ")
                        delete_file(username, filename)
                    elif action == "5":
                        break
            else:
                print("\nInvalid credentials.")
        elif choice == "2":
            username = input("Choose a username: ")
            while True:
                password = getpass.getpass("Choose a password: ")
                if validate_password(password):
                    break
                print("Password must be at least 8 characters long and include an uppercase letter, a number, and a special character.")
            confirm_pass = getpass.getpass("Confirm password: ")
            if password == confirm_pass:
                save_user(username, password)
                print("\nRegistration successful!")
            else:
                print("\nPasswords do not match. Please try again.")
        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
