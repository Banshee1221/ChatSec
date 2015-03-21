import socket
import sys
from thread import *
import pickle
import logging
import os

from Crypto.Cipher import AES

from AES import *


logging.basicConfig(stream=sys.stderr, level=logging.INFO)
HOST = ''  # Symbolic name meaning all available interfaces
PORT = 8888  # Arbitrary non-privileged port
CLIENTS = {}
KEYS = {'1': '(e\xd0\t\xacn\xa8k}\xbe\x80s)>m\x83', '2': '({l\xa8\xee\x00\xf0\xe6b\xb8\n\x96\xb8\xcc\xd20',
        '3': '\xbaB\x80\x96\x84\x15*\x1b\x0e\xc9\xbb\xbdF~\x8a9'}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # <- must be called before bind
print 'Socket created'

# Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message: ' + msg[1]
    sys.exit()

print 'Socket bind complete'

# Start listening on socket
s.listen(10)
print 'Socket now listening'

# Function for handling connections. This will be used to create threads
def clientthread(conn, addr):
    # Sending message to connected client
    # conn.send('Welcome to the server. Type something and hit enter\n')  # send only takes string

    # infinite loop so that function do not terminate and thread do not end.
    while True:
        initAuth = ''
        # Receiving from client
        data = ''
        try:
            data = conn.recv(4096)
        except socket.error:
            logging.info("Client at %s disconnected with socket error.", addr)
            conn.close()
        if not data:
            logging.info("Client at %s closed.", addr)
            break

        print "Received: " + data.replace('\n', '').replace('\r', '')
        try:
            initAuth = pickle.loads(data)
            logging.info("Loaded data: %s", initAuth)
            if initAuth['type'] == 'new conn':
                if str(initAuth['uid']) in CLIENTS:
                    logging.info("User already in connected list")
                else:
                    logging.info("Client incoming, checking validity")
                    tempCiph = AES.new(KEYS[str(initAuth['uid'])])
                    checker = decrypt(initAuth['encuid'], tempCiph)
                    if str(checker) == str(initAuth['uid']):
                        logging.info("User validated!")
                    else:
                        logging.info("ISSUES! WRONG USER!")
                        continue
                    logging.info("Incoming dict: %s", initAuth)
                    CLIENTS[str(initAuth['uid'])] = {'IP': initAuth['ip'], 'PORT': int(initAuth['port'])}
                    logging.info("Added user %s to the connected list with ip: %s, port: %s", str(initAuth['uid']),
                                 str(initAuth['ip']), initAuth['port'])
                    conn.sendall(pickle.dumps(CLIENTS)) # need to work out how to broadcast this. Maybe encrypt before sending
            elif initAuth['type'] == 'session':
                logging.info("Loaded data from the client: %s", initAuth)
                # Verify the target client
                clientID = initAuth['uid']
                otheruid = initAuth['otheruid']
                nonce = initAuth['nonce']
                if otheruid not in KEYS:
                    logging.info("No key for client %s", otheruid)
                    continue
                clientRedirCiph = AES.new(KEYS[otheruid])
                decr = pickle.loads(decrypt(initAuth['enc'], clientRedirCiph))
                if otheruid != decr['otheruid']:
                    logging.info("Target uid mismatch! Invalid request from uid %s to connect to %s", clientID, otheruid)
                
                sessKey = os.urandom(16)
                logging.info("Generated random session key: %s", sessKey)
                # expire = initAuth['expire']
                clientCiph = AES.new(KEYS[clientID])
                logging.info("Generated client cipher block: %s", clientRedirCiph)
                passOn = {'sKey': sessKey, 'uid': clientID, 'nonce': decr['nonce']}
                passOnEnc = encrypt(passOn, clientRedirCiph)
                logging.info("Encrypted Kab, A and nonce of B with B's key")

                response = {'nonce': nonce,
                            'sKey': sessKey,
                            'otheruid': otheruid,
                            'enc': passOnEnc}
                responseEnc = encrypt(pickle.dumps(response), clientCiph)
                conn.sendall(responseEnc)
            else:
                logging.info('Invalid message received: %s', initAuth)

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
    start_new_thread(clientthread, (conn,addr))

s.close()