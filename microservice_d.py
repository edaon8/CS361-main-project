import zmq
import os

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5558")

print("Starting File Type Detector microservice...")

while True:
    filepath = socket.recv_string()
    if os.path.exists(filepath):
        file_type = os.path.splitext(filepath)[-1]
        socket.send_string(file_type if file_type else "Unknown")
        print(f"Sending file type for {filepath}: {file_type if file_type else 'Unknown'}")
    else:
        socket.send_string("Error: File not found.")
        print(f"Error: File not found.")
