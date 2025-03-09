import zmq
import time
import datetime

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5557")

print("Starting Timestamp Generator microservice...")

while True:
    socket.recv()  # Wait for request
    timestamp = str(int(time.time()))
    socket.send_string(timestamp) # sent as an int
    # Code for printing timestamp correctly
    timestamp_int = int(timestamp)
    readable_timestamp = datetime.datetime.fromtimestamp(timestamp_int).strftime('%Y-%m-%d %H:%M:%S')
    print(f"Timestamp requested at {readable_timestamp}: {timestamp}")
