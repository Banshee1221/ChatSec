import socket
import sys
from thread import *
import logging
import os
from AES import *
from comm import *


logging.basicConfig(stream=sys.stderr, level=logging.INFO)
HOST = ''  # Symbolic name meaning all available interfaces
PORT = 8888  # Arbitrary non-privileged port
CLIENTS = {}
KEYS = {'1': '(e\xd0\t\xacn\xa8k}\xbe\x80s)>m\x83', '2': '({l\xa8\xee\x00\xf0\xe6b\xb8\n\x96\xb8\xcc\xd20',
        '3': '\xbaB\x80\x96\x84\x15*\x1b\x0e\xc9\xbb\xbdF~\x8a9'}

def broadcast(msg, new_client):
    """Send the encrypted clients list to all of the connected clients
    :return: None"""
    for client in CLIENTS:
        # skip the newly connected client - it's handled separately
        if client == new_client:
            continue
        clients_enc = encrypt(CLIENTS, KEYS[client])
        msg = {'type': 'clients',
               'data': clients_enc}
        conn = connect(CLIENTS[client])
        send(msg, conn)
        conn.close()

# Function for handling connections. This will be used to create threads
def clientthread(conn, addr):
    # Sending message to connected client
    # infinite loop so that function do not terminate and thread do not end.
    while True:
        initAuth = ''
        # Receiving from client
        data = ''
        try:
            data = receive(conn)
        except socket.error:
            logging.info("Client at %s disconnected with socket error.", addr)
            print CLIENTS
            print addr
            conn.close()
        if not data:
            logging.info("Client at %s closed.", addr)
            print CLIENTS
            print addr
            break

        logging.info("Received: %s", data)
        try:
            initAuth = data
            logging.info("Loaded data: %s", initAuth)
            
            if initAuth['type'] == 'new conn':
                # Authenticate the client with the server
                if str(initAuth['uid']) in CLIENTS:
                    logging.info("User already in connected list")
                else:
                    logging.info("Client incoming, checking validity")
                    checker = decrypt(initAuth['encuid'], KEYS[initAuth['uid']])
                    if str(checker) == str(initAuth['uid']):
                        logging.info("User validated!")
                    else:
                        logging.info("ISSUES! WRONG USER!")
                        continue
                    logging.info("Incoming dict: %s", initAuth)
                    CLIENTS[str(initAuth['uid'])] = (initAuth['ip'], int(initAuth['port']))
                    logging.info("Added user %s to the connected list with ip: %s, port: %s", str(initAuth['uid']),
                                 str(initAuth['ip']), initAuth['port'])
                    send(CLIENTS, conn) # send reply to new clients separately
                    broadcast(CLIENTS, initAuth['uid']) # <- focus here
            
            elif initAuth['type'] == 'session':
                # Respond with a new session key
                logging.info("Loaded data from the client: %s", initAuth)
                clientID = initAuth['uid']
                otheruid = initAuth['otheruid']
                nonce = initAuth['nonce']

                # Verify the target client
                if otheruid not in KEYS:
                    logging.info("No key for client %s", otheruid)
                    continue
                decr = decrypt(initAuth['enc'], KEYS[otheruid])
                logging.info("Decrypted B's package with type: %s", type(decr))
                if clientID != decr['uid']:
                    logging.info("Target uid mismatch! Invalid request from uid %s to connect to %s", clientID, otheruid)
                
                # Generate new session key and package it for the other clients
                sessKey = os.urandom(16)
                logging.info("Generated random session key: %s", sessKey)
                passOn = {'sKey': sessKey, 'uid': clientID, 'nonce': decr['nonce']}
                passOnEnc = encrypt(passOn, KEYS[otheruid])
                logging.info("Encrypted session key, uid of A and nonce of B with B's key")

                response = {'nonce': nonce,
                            'sKey': sessKey,
                            'otheruid': otheruid,
                            'enc': passOnEnc}
                responseEnc = encrypt(response, KEYS[clientID])
                logging.info("Sending response to client: %s", responseEnc)
                send(responseEnc, conn)
                logging.info("Sent response to client %s", clientID)
            
            elif initAuth['type'] == 'dc':
                # client allegedly disconnecting
                logging.info("Trying to disconnect client with uid %s", initAuth['uid'])
                uid = decrypt(initAuth['encuid'], KEYS[initAuth['uid']])
                if uid == initAuth['uid']:
                    del CLIENTS[uid]
                    logging.info("Disconnected client with uid %s", uid)
                    broadcast(CLIENTS, uid)
            
            else:
                logging.info('Invalid message received: %s', initAuth)

        except IndexError:
            logging.info("Non-auth. Rejected.")

    # came out of loop
    conn.close()

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

# now keep talking with the client
while 1:
    # wait to accept a connection - blocking call
    conn, addr = s.accept()
    print 'Connected with ' + addr[0] + ':' + str(addr[1])

    # start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
    start_new_thread(clientthread, (conn,addr))

s.close()