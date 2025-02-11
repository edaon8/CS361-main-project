import re

# By Ethan Daon
# CS 361


def welcome():
    print("\n-- Welcome -----------------------------------------\n")
    print("Welcome to the Secure File Storage System (SSFS)!\n")
    print("Here you can safely encrypt and decrypt your files \nusing the SHA-256 encryption scheme to store them \nfrom any potential attacks.\n")
    print("Please select one of the options below (Type 1-3):")
    print("[1] Login")
    print("[2] Register")
    print("[3] Exit")

def login():
    print("\n-- Login --------------------------------------------\n")
    print("Please enter your credentials to login.")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    while True:
        # Here, we should add actual checks against stored user data, e.g.:
        # if username in database and database[username] == password:
        if username == "user" and password == "test":
            print("\nLogging in...")
            return True  # Return True to indicate successful login
        else: 
            print("\n-- Login --------------------------------------------\n")
            print("Incorrect credentials, please try again or type '1' to return to the welcome page.")
            username = input("Enter your username: ")
            if username == "1":
                return False
            password = input("Enter your password: ")
            if password == "1":
                return False

def register():
    print("\n-- Register Screen ------------------------------------\n")
    print("To create your account, please enter a username and password or type '1' to return to the welcome page.")
    print("\nYour username must consist of only letters and numbers and be 8-16 characters long.")
    print("Your password must contain an uppercase letter, a number, and a special character (!@#$%^&*+-/?.,:;) and be 12-32 characters long.")
    
    while True:
        username = input("Enter a username: ")
        if username == "1":
            return
        elif len(username) < 8 or len(username) > 16 or not username.isalnum():
            print("Invalid username, please try again.")
        else:
            break

    while True:
        password = input("Enter a password: ")
        if len(password) < 12 or len(password) > 32 or not re.search(r'[A-Z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*+\-/?.,:;]', password):
            print("Invalid password, please try again.")
        else:
            break

    while True:
        confirm_password = input("Confirm your password: ")
        if password != confirm_password:
            print("Passwords do not match. Try again.")
        else:
            # print("Registration successful. Returning to login.")
            return True

def dashboard(username):
    while True:
        print("\n-- Dashboard --------------------------------------------\n")
        print(f"Hi {username}! Please select an option from the list below:")
        print("[1] Encrypt a file")
        print("[2] View encrypted files")
        print("[3] Logout")
        choice = input("Enter your choice: ")

        if choice == "1":
            encrypt_file()
        elif choice == "2":
            view_encrypted_files()
        elif choice == "3":
            print("Logging out...")
            return # should go to login screen
        else:
            print("Invalid choice. Try again.")

def encrypt_file():
    print("\n-- Encrypt File ---------------------------------------\n")
    file_path = input("Enter the file path to encrypt: ")
    # TODO read file path and confirm file exists
    # TODO encryption and writing to new file
    print(f"\nEncrypting and storing {file_path}...")
    print("\nFile encrypted successfully. Returning to dashboard.")

def view_encrypted_files():
    # TODO function that finds files from dir
    files = ["file1.txt", "file2.txt"]  # Example files
    while True:
        print("\n-- Encrypted Files -------------------------------------\n")
        for idx, f in enumerate(files):
            print(f"[{idx + 1}] {f}")
        print("[0] Back to Dashboard")

        choice = input("Enter file number to view details, or 0 to go back: ")
        if choice == "0":
            break
        elif choice.isdigit() and 1 <= int(choice) <= len(files):
            file_details(files[int(choice) - 1])
        else:
            print("Invalid choice. Try again.")

def file_details(file_name):
    print(f"\n-- File Details: {file_name} ----------------------------------\n")
    # TODO actually get this data from the file
    print("File Name:", file_name)
    print("Size: 12 KB")
    print("Encryption Status: Encrypted")
    print("\nSelect an option:")

    while True:
        print("[1] Decrypt file")
        print("[2] Delete file")
        print("[3] Back to File List")
        choice = input("Enter your choice: ")

        if choice == "1":
            # TODO actually decrypt the file
            print(f"\nDecrypting {file_name}...")
            print("\nFile decrypted successfully.")
        elif choice == "2":
            # TODO add a pop up that confirms if they want to delete the file
            print(f"Deleting {file_name}...")
            print("File deleted successfully.")
            break
        elif choice == "3":
            break
        else:
            print("Invalid choice. Try again.")

def main():
    logged_in = False
    username = "user"
    while True:
        welcome()
        choice = input("Enter your choice: ")

        if choice == "1":
            if login():
                logged_in = True
                dashboard(username)
        elif choice == "2":
            if register():
                logged_in = True
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

        if logged_in:
            break

    

if __name__ == "__main__":
    main()
