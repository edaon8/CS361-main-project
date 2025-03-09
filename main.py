import zmq
import struct
import os
import re
import bcrypt
import json
import getpass
import datetime
from cryptography.fernet import Fernet

# Directory setup
USER_DATA_FILE = "users.json"
ENCRYPTED_DIR = "encrypted_files"
ALLOWED_EXTENSIONS = {'.txt'}

os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def request_service(address, message):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(address)
    socket.setsockopt(zmq.RCVTIMEO, 2000)
    try:
        socket.send_string(message)
        return socket.recv_string()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        socket.close()
        context.term()

def get_rand_num(num_limit): # Microservice A
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://localhost:5555")
    socket.setsockopt(zmq.RCVTIMEO, 2000) # timeout = 2s
    try:
        socket.send(struct.pack("i", num_limit))
        random_num = socket.recv_string().split()[-1] # get the last word (the number)
        return int(random_num)
    except Exception as e:
        print(f"Error: {e}")
        return -1
    finally:
        socket.close()
        context.term()

def request_file_size(filepath, username, is_encrypted=False): # Microservice B
    # Normalize the path and replace w/ forward slashes
    req = filepath.replace("\\", "/")
    message = f"{req}:{username}:{is_encrypted}"
    return request_service("tcp://localhost:5556", message)

def request_timestamp(): # Microservice C
    timestamp = request_service("tcp://localhost:5557", "Requesting timestamp")
    if timestamp:
        timestamp_int = int(timestamp)
        readable_timestamp = datetime.datetime.fromtimestamp(timestamp_int).strftime('%Y-%m-%d %H:%M:%S')
    return readable_timestamp

def request_file_type(filepath): # Microservice D
    filepath = filepath.lstrip("/\\")
    return request_service("tcp://localhost:5558", filepath)

def is_valid_file(filepath):
    file_type = request_file_type(filepath)
    return file_type.lower() in ALLOWED_EXTENSIONS

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
    filepath = filepath.lstrip("/\\")
    
    if not os.path.exists(filepath):
        print(f"The file at '{filepath}' was not found.")
        return
    
    if not is_valid_file(filepath):
        print(f"Error: {filepath} is not a valid file type for encryption.")
        return

    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        encrypted_data = fernet.encrypt(file.read())
    filename = os.path.basename(filepath) + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)
    
    timestamp = request_timestamp()
    print(f"\nFile decrypted and saved as: {encrypted_path} at {timestamp}")
    #print(f"\nFile encrypted and stored as: {encrypted_path} at {timestamp}")

def decrypt_file(username, filename, key):
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename + ".enc")
    print(f"Encrypted path: {encrypted_path}") # test comment
    if not os.path.exists(encrypted_path):
        print("File not found.")
        return
    
    try:
        fernet = Fernet(key)
        with open(encrypted_path, "rb") as file:
            decrypted_data = fernet.decrypt(file.read())
        output_path = filename.replace(".enc", "")
        with open(output_path, "wb") as file:
            file.write(decrypted_data)
    except Exception as e:
        print(f"Error during decryption: {e}")
        return
    
    timestamp = request_timestamp()
    file_size = request_file_size(output_path, username, is_encrypted=False)
    print(f"\nFile decrypted and saved as: {output_path} at {timestamp}")
    print("Decrypted file content:")
    print(decrypted_data.decode(errors='ignore'))
    print(f"File size: {file_size}")

def list_files(username):
    files = [f for f in os.listdir(ENCRYPTED_DIR) if f.startswith(username + "_")]
    if not files:
        print("No encrypted files found.")
        return

    print("\nEncrypted Files:")
    for file in files:
        rel_filepath = os.path.normpath(os.path.join(ENCRYPTED_DIR, file))
        file_size = request_file_size(rel_filepath, username, is_encrypted=True)
        print(f"- {file.replace(username + '_', '')} ({file_size} bytes)")

def delete_file(username, filename):
    if not filename.endswith(".enc"):
        filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_DIR, username + "_" + filename)
    if not os.path.exists(encrypted_path):
        print("File not found.")
        return
    print(f"Are you sure you wish to delete {filename}? [1] Yes [0] No")
    confirmation = input("Choose: ")
    if confirmation == "1":
        os.remove(encrypted_path)
        print("\nFile deleted successfully.")
    else:
        print("\nFile deletion cancelled.")

def encrypt_random_file(username, key, file_dir):
    if not os.path.exists(file_dir):
        print("Error: Specified directory does not exist.")
        return
    files = [f for f in os.listdir(file_dir) if os.path.isfile(os.path.join(file_dir, f)) and not f.endswith(".enc")]
    if not files:
        print("No available files to encrypt in the specified directory.")
        return
    rand_index = get_rand_num(len(files)-1)
    if rand_index == -1:
        print("Microservice unavailable, exiting...")
        return
    selected_file = files[rand_index]
    encrypt_file(username, os.path.join(file_dir, selected_file), key)

def main():
    print("\n\nWelcome to Secure File Storage System (SSFS)!")
    print("""_       __        ___       ___       _____
 )  ____) \    ___)  )  ____)  )  ____)    
(  (___    |  (__   (  (___   (  (___      
 \___  \   |   __)   \___  \   \___  \     
 ____)  )  |  (      ____)  )  ____)  )    
(      (__/    \____(      (__(      (_____
          """)
    print("Here you can safely encrypt and decrypt your files using the Fernet\nencryption scheme.")
    while True:
        print("\nPlease select an option [1-3]:")
        print("  [1] Login  [2] Register  [3] Exit")
        choice = input("Choose: ")
        if choice == "1":
            print("Please enter your credentials.")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            key = authenticate(username, password)
            if key:
                while True:
                    print(f"\nWelcome to the dashboard {username}! Here you can encrypt files, view encrypted files,")
                    print("decrypt files, and manage your existing files.")
                    print("\nPlease select an option [1-6]:")
                    print("  [1] Encrypt File  [2] View Encrypted Files  [3] Decrypt File  [4] Delete File")
                    print("  [5] Encrypt Random File  [6] Logout")
                    action = input("Choose: ")
                    if action == "1":
                        filepath = input("Enter the file path of the file you wish to encrypt: ")
                        encrypt_file(username, filepath, key)
                    elif action == "2":
                        list_files(username)
                    elif action == "3":
                        filename = input("\nEnter the name of the file to decrypt: ")
                        decrypt_file(username, filename, key)
                    elif action == "4":
                        filename = input("\nEnter the name of the file to delete: ")
                        delete_file(username, filename)
                    elif action == "5":
                        file_dir = input("\nEnter the path to the directory you wish to encrypt from: ")
                        encrypt_random_file(username, key, file_dir)
                    elif action == "6":
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
