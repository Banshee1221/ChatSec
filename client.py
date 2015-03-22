__author__ = 'Eugene'

import socket
import random
import pickle
import logging
import sys
from thread import *
import threading
from Crypto.Cipher import AES
from AES import *


logging.basicConfig(stream=sys.stderr, level=logging.INFO)


class Client():
    clientID = 0
    sharedKey = 0 # key pre-shared with the server
    cipher = '' # AES cipher for server messages
    IP = 0
    port = 0
    listenOnly = False
    cli_sock = None # 'client' type socket for sending messages to the server
    others = {} # clients currently listening for messages
    keyring = {} # session keys shared with other clients
    # maybe combine others and keyring by making others[i] map to a dict with keys 'address' and 'key'
    nonces = {} # nonces used for each client's session ('session nonces' used to check that both parties have the same key)
    sec_nonces = {} # nonces only the server can see
    listenSock = '' # server socket for client listening to incoming client connections
    listenIP = ''
    listenPORT = ''
    threads = []
    chatFlag = False
    clientConn = ''
    clientAddr = ''

    def __init__(self, ID, key, IP, port, listenOnly=False):
        self.clientID = ID
        self.sharedKey = key
        self.cipher = AES.new(self.sharedKey)
        self.IP = IP
        self.port = port
        self.listenOnly = listenOnly
        
    def run(self):
        # Binding own port and connecting to server
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Connecting to server with IP: " + str(self.IP) + ", PORT: " + str(self.port)
        self.cli_sock.connect((self.IP, self.port))
        print "Success! Connected to server"

        # ensure that listenSock is set up before identify sends socket info to the server
        setup = self.setupListen(('127.0.0.1', 0))
        self.listenSock = setup['sock']
        self.listenIP, self.listenPORT = setup['address']
        start_new_thread(self.listenToClients, ())
        print "Self-listening started"
        
        self.identify()
        self.menu()

        self.cli_sock.close()

    def identify(self):
        uid = self.clientID
        idEnc = encrypt(uid, self.cipher)
        payload = {'type': 'new conn',
                   'uid': uid,
                   'ip': self.listenIP,
                   'port': self.listenPORT,
                   'encuid': idEnc}
        self.send(pickle.dumps(payload)) # TODO: encrypt IP and port num to combat dos
        self.others = pickle.loads(self.cli_sock.recv(1024))

    def menu(self):
        choice = False
        while not choice:
            print "\nSelect one of the following clients to chat to:"
            for each in self.others:
                print each
            choice = str(raw_input(":: "))
            if choice not in self.others:
                print "That client is not connected."
                choice = False
            if choice == self.clientID:
                print "You can't chat with yourself."
                choice = False
            dictRet = self.others[choice]
            logging.info("Chosen %s", str(dictRet))
            if self.authCli(choice, dictRet['IP'], dictRet['PORT']):
                print "Starting messaging"
                # Enter messaging state here
                # self.chat()
            else:
                if choice not in self.others:
                    print "That client is not connected."
                    choice = False
                if choice == self.clientID:
                    print "You can't chat with yourself."
                    choice = False
                dictRet = self.others[choice]
                logging.info("Chosen %s", str(dictRet))
                if self.authCli(choice, dictRet['IP'], dictRet['PORT']):
                    print "Starting messaging"
                    threading.Thread(target=self.sender) # Trying to establish conn to send and receive messages here
                else:
                    print "Authentication failed."
                    choice = False

    def authCli(self, cli_id, cli_ip, cli_port):
        # Send initial request to other client
        tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_sock.connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        init = {'type': 'new conn',
                'uid': self.clientID}
        tmp_sock.sendall(pickle.dumps(init))
        logging.info("Sent ID to the target client")
        enc = tmp_sock.recv(1024)
        tmp_sock.close()
        logging.info("Info received from client: %s", enc.replace("\n", '').replace("\r", ''))

        # Pass on package to the server, then send reply (with session key)
        # to the other client
        package = self.authSrv(cli_id, enc)
        if not package:
            return False
        toSend = {'type': 'new nonce',
                  'package': package}
        # Currently reconnecting manually, this should be done through a connect function
        tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_sock.connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        tmp_sock.sendall(pickle.dumps(toSend))
        logging.info("Sent session key to client %s at %s", cli_id, (cli_ip, cli_port))

        # Confirm possession of session key by sending nonce + 1
        incoming = tmp_sock.recv(1024)
        tmp_sock.close()
        tmp_cipher = AES.new(self.keyring[cli_id])
        sessionNonce = decrypt(incoming, tmp_cipher) # note: encrypted nonce is sent alone, not in a dict
        logging.info("Nonce received: %s", sessionNonce)
        self.nonces[cli_id] = sessionNonce
        nonce_conf = encrypt(sessionNonce+1, tmp_cipher)

        tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_sock.connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        tmp_sock.sendall(pickle.dumps({'type': 'conf',
                                       'uid': self.clientID,
                                       'nonce': nonce_conf}))
        tmp_sock.close()
        logging.info("Sent modified nonce as confirmation")

        return True

    def authSrv(self, who, encData):
        # Send request for session key to server
        nonce = random.randrange(1, 100000000)
        # expiry = 50000
        packet = pickle.dumps({'type': 'session',
                               'uid': self.clientID,
                               'otheruid': who,
                               'nonce': nonce,
                               'enc': encData})
        self.send(packet)
        logging.info("Sent request to server")

        # Unpack session key and return package for other client
        recvEnc = self.cli_sock.recv(4096)
        logging.info("Received data from CA server: %s", recvEnc)
        decr = decrypt(recvEnc, AES.new(self.sharedKey))
        logging.info("Decoded information from the CA serv: %s", decr)
        if decr['otheruid'] != who or decr['nonce'] != nonce:
            logging.info("Invalid reply from server")
            return False
        self.keyring[who] = decr['sKey']

        return decr['enc']

    def send(self, msg):
        self.cli_sock.sendall(msg)

    def setupListen(self, address):
        """Sets up a socket to listen for messages at the given ip/port pair.
        :return: A dictionary with the listening socket and its ip and port"""
        lSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # <- must be called before bind
        lSoc.bind(address)
        temp = lSoc.getsockname()
        logging.info("Binding socket: %s", str(temp))
        # ip = temp[0]
        # port = temp[1]
        lSoc.listen(5)        
        return {'sock': lSoc,
                'address': temp}

    def listenToClients(self):
        while True:
            conn, addr = self.listenSock.accept()
            self.clientConn, self.ClientAddr = conn, addr
            logging.info("Incoming connection with %s", addr)
            data = pickle.loads(conn.recv(1024)) # <- Slightly insecure, could be used to load random crap I think. Rather handle this in a separate receive method
            if not data:
                break
            logging.info("Received data: %s", data)
            if data['type'] == 'new conn':
                self.chatFlag = True
                # Another client is requesting a new connection
                nonce = random.randrange(1, 100000000) # <- need to store this and check it later on (see below)
                self.sec_nonces[data['uid']] = nonce
                toSend = encrypt(pickle.dumps({'uid': data['uid'], 'nonce': nonce}), self.cipher)
                logging.info("Sending information [%s] back to client", toSend)
                conn.sendall(toSend)
                logging.info("Encrypted info sent")
            elif data['type'] == 'new nonce':
                # Confirmation package from server, delivered by another client
                # Add the session key to the keyring
                package = decrypt(data['package'], self.cipher)
                self.keyring[package['uid']] = package['sKey']

                # check that the nonce is the same as the one initially sent
                if self.sec_nonces[package['uid']] != package['nonce']:
                    logging.info("Server's nonce was not fresh")
                    continue

                # Send a confirmation nonce
                cipher = AES.new(self.keyring[package['uid']])
                nonce = random.randrange(1, 100000000)
                self.nonces[package['uid']] = nonce
                nonceEnc = encrypt(nonce, cipher)
                conn.sendall(nonceEnc) # note: encrypted nonce is sent alone, not in a dict
                logging.info("Session nonce sent")
            elif data['type'] == 'conf':
                tmp_cipher = AES.new(self.keyring[data['uid']])
                nonce = decrypt(data['nonce'], tmp_cipher)
                if nonce != self.nonces[data['uid']] + 1:
                    logging("Confirmation nonce incorrect! connection rejected")
                    continue
                logging.info("Nonce confirmed. Starting messaging")
                threading.Thread(target=self.receiver) # Start the listener that is supposed to return messages
                # Enter messaging state here
                # self.chat()
            else:
                logging.info("Message type not recognised")
                continue

        conn.close()

    # TODO: use this for the messaging state
    def chat(self):
        logging.info('Listening for info')
        conn, addr = self.listenSock.accept()
        logging.info('Received connection: %s, address: %s', conn, addr)
        while True:
            toSend = str(raw_input())
            conn.sendall(toSend)
        conn.close()

    def receiver(self):
        conn, addr = self.clientConn, self.clientAddr
        logging.info('Established to: %s, address: %s for listening', conn, addr)
        while True:
            print conn.recv(4096)
        conn.close()
