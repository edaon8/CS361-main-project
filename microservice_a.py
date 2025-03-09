#   Nicks Microservice
#   Binds REP socket to tcp://*:5555

import time
import zmq
import random
import struct

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5555")

print("Starting Random Number Generator microservice...")

while True:
    #  Wait for next request from client
    received_data = socket.recv()
    received_integer = struct.unpack("i", received_data)[0]
    print("Generating a random number between 0 and " + str(received_integer))
    time.sleep(1)
    random_integer = random.randint(0, received_integer)
    print("Your random number between 0 and " + str(received_integer) + " is " + str(random_integer))
    socket.send_string("Your random number between 0 and " + str(received_integer) + " is " + str(random_integer))
