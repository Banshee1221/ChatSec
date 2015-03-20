import socket
import sys
from thread import *
import pickle
from AES import *
from Crypto.Cipher import AES
import random
import logging
import os


logging.basicConfig(stream=sys.stderr, level=logging.INFO)
HOST = ''  # Symbolic name meaning all available interfaces
PORT = 8888  # Arbitrary non-privileged port
KEYS = {1: '(e\xd0\t\xacn\xa8k}\xbe\x80s)>m\x83', 2: '({l\xa8\xee\x00\xf0\xe6b\xb8\n\x96\xb8\xcc\xd20', 3: '\xbaB\x80\x96\x84\x15*\x1b\x0e\xc9\xbb\xbdF~\x8a9'}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Socket created'

# Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

print 'Socket bind complete'

# Start listening on socket
s.listen(10)
print 'Socket now listening'

# Function for handling connections. This will be used to create threads
def clientthread(conn):
    # Sending message to connected client
    # conn.send('Welcome to the server. Type something and hit enter\n')  # send only takes string

    # infinite loop so that function do not terminate and thread do not end.
    while True:
        initAuth = ''
        # Receiving from client
        data = ''
        try:
            data = conn.recv(1024)
        except socket.error:
            logging.info("Client disconnected.")
            conn.close()
        if not data:
            break

        print "Received: "+data
        try:
            initAuth = pickle.loads(data)
            logging.info("Loaded data from the client: %s", initAuth)
            sessKey = os.urandom(16)
            logging.info("Generated random session key: %s", sessKey)
            clientID = initAuth[0]
            redirID = initAuth[1]
            expire = initAuth[2]
            nonce = initAuth[3]
            clientRedirCiph = AES.new(KEYS[int(redirID)])
            clientCiph = AES.new(KEYS[int(clientID)])
            logging.info("Generated client cipher block: %s", clientRedirCiph)
            passOn = [sessKey, clientID]
            passOnEnc = encrypt(passOn, clientRedirCiph)
            logging.info("Encrypted Kab, A with B key")

            response = [nonce, sessKey, redirID, passOnEnc]
            responseEnc = encrypt(response, clientCiph)
            conn.sendall(pickle.dumps(responseEnc))

        except IndexError:
            logging.info("Non-auth. Rejected.")

    # came out of loop
    conn.close()

# now keep talking with the client
while 1:
    # wait to accept a connection - blocking call
    conn, addr = s.accept()
    print 'Connected with ' + addr[0] + ':' + str(addr[1])

    # start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
    start_new_thread(clientthread, (conn,))

s.close()