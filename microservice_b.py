import zmq
import os

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5556")

ENCRYPTED_DIR = "encrypted_files"

print("Starting File Size Checker microservice...")

while True:
    message = socket.recv_string().strip()
    rel_filepath, username, is_encrypted = message.split(":")

    rel_filepath = os.path.normpath(rel_filepath)
    filepath = os.path.basename(rel_filepath)

    print(f"Checking file: {filepath}")

    if is_encrypted.lower() == "true":
        # encrypted_filename = f"{username}_{filepath}"
        filepath = os.path.join(ENCRYPTED_DIR, filepath)

        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            socket.send_string(str(size))
            print(f"Sending file size for {filepath}: {size} Bytes")
        else:
            socket.send_string("Error: File not found in encrypted directory.")
            print(f"Error: File not found in encrypted directory: {filepath}")
    
    else: # non-encrypted file
        filepath = os.path.join(".", rel_filepath)

        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            socket.send_string(str(size))
            print(f"Sending file size for {filepath}: {size} Bytes")
        else:
            socket.send_string("Error: File not found.")
            print(f"Error: File not found: {filepath}")


