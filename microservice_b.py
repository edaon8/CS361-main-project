import zmq
import os

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5556")

print("Starting File Size Checker microservice...")

while True:
    filepath = socket.recv_string()
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        socket.send_string(str(size))
        print(f"Sending file size for {filepath}: {size} Bytes")
    else:
        socket.send_string("Error: File not found.")


