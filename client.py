__author__ = 'Eugene'

import socket
import random
import pickle
import logging
import sys
import time
from thread import *
import threading
from Crypto.Cipher import AES
from AES import *
from comm import *


logging.basicConfig(stream=sys.stderr, level=logging.INFO)


class Client():
    ID = 0
    server_ip = 0
    port = 0

    sharedKey = 0 # key pre-shared with the server
    cipher = '' # AES cipher for server messages
    cli_sock = None # 'client' type socket for sending messages to the server

    others = {} # addresses of clients currently listening for messages
    keyring = {} # session keys shared with other clients
    # maybe combine others and keyring by making others[i] map to a dict with keys 'address' and 'key'
    nonces = {} # nonces used for each client's session ('session nonces' used to check that both parties have the same key)
    sec_nonces = {} # nonces sent securely to the server can see
    
    listenSock = '' # server socket for client listening to incoming client connections
    listenIP = ''
    listenPORT = ''

    chatLock = allocate_lock()
    chatUID = ''

    def __init__(self, ID, key, server_ip, server_port):
        self.ID = ID
        self.sharedKey = key
        self.cipher = AES.new(self.sharedKey)
        self.server_ip = server_ip
        self.server_port = server_port
        
    def run(self):
        # Binding own port and connecting to server
        print "Connecting to server with IP: " + str(self.server_ip) + ", PORT: " + str(self.server_port)
        self.cli_sock = connect((self.server_ip, self.server_port))
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
        uid = self.ID
        idEnc = encrypt(uid, self.cipher)
        payload = {'type': 'new conn',
                   'uid': uid,
                   'ip': self.listenIP,
                   'port': self.listenPORT,
                   'encuid': idEnc}
        send(payload, self.cli_sock) # TODO: encrypt IP and port num to combat dos
        self.others = receive(self.cli_sock) # <- TODO: put this in the listen thread

    def menu(self):
        if not self.others:
            print "Server not available. Check connection."
            exit()
        choice = False
        while not choice:
            if self.chatLock.locked():
                # logging.info("LOCK1 FOUND")
                time.sleep(1)
                continue
            print "\nSelect one of the following clients to chat to:"
            for each in self.others:
                print each
            choice = str(raw_input(":: "))
            if self.chatLock.locked():
                # logging.info("LOCK2 FOUND")
                choice = False
                continue
            if choice not in self.others:
                print "That client is not connected."
                choice = False
                continue
            if choice == self.ID:
                print "You can't chat with yourself."
                choice = False
                continue
            address = self.others[choice]
            logging.info("Chosen %s", str(address))
            if self.authCli(choice, address[0], address[1]):
                print "Starting messaging"
                choice = self.chat()
            else:
                print "Authentication failed."
                choice = False

    def authCli(self, cli_id, cli_ip, cli_port):
        # Send initial request to other client
        tmp_sock = connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        init = {'type': 'new conn',
                'uid': self.ID}
        send(init, tmp_sock)
        logging.info("Sent ID to the target client")
        enc = receive(tmp_sock)
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
        tmp_sock = connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        send(toSend, tmp_sock)
        logging.info("Sent session key to client %s at %s", cli_id, (cli_ip, cli_port))

        # Confirm possession of session key by sending nonce + 1
        incoming = receive(tmp_sock)
        tmp_sock.close()
        tmp_cipher = AES.new(self.keyring[cli_id])
        sessionNonce = decrypt(incoming, tmp_cipher) # note: encrypted nonce is sent alone, not in a dict
        logging.info("Nonce received: %s", sessionNonce)
        self.nonces[cli_id] = sessionNonce
        nonce_conf = encrypt(sessionNonce+1, tmp_cipher)

        tmp_sock = connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        conf = {'type': 'conf',
                'uid': self.ID,
                'nonce': nonce_conf}
        send(conf, tmp_sock)
        tmp_sock.close()
        self.chatUID = cli_id
        logging.info("Sent modified nonce as confirmation")

        return True

    def authSrv(self, who, encData):
        # Send request for session key to server
        nonce = random.randrange(1, 100000000)
        # expiry = 50000
        packet = {'type': 'session',
                  'uid': self.ID,
                  'otheruid': who,
                  'nonce': nonce,
                  'enc': encData}
        send(packet, self.cli_sock)
        logging.info("Sent request to server")

        # Unpack session key and return package for other client
        recvEnc = receive(self.cli_sock)
        logging.info("Received data from CA server: %s", recvEnc)
        decr = decrypt(recvEnc, AES.new(self.sharedKey))
        logging.info("Decoded information from the CA serv: %s", decr)
        if decr['otheruid'] != who or decr['nonce'] != nonce:
            logging.info("Invalid reply from server")
            return False
        self.keyring[who] = decr['sKey']

        return decr['enc']

    # def send(self, msg):
    #     self.cli_sock.sendall(msg)

    def setupListen(self, address):
        """Sets up a socket to listen for messages at the given ip/port pair.
        :return: A dictionary with the listening socket and its ip and port"""
        lSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # <- must be called before bind
        lSoc.bind(address)
        temp = lSoc.getsockname()
        logging.info("Bound socket: %s", str(temp))
        lSoc.listen(5)        
        return {'sock': lSoc,
                'address': temp}

    def listenToClients(self):
        while True:
            conn, addr = self.listenSock.accept()
            logging.info("Incoming connection with %s", addr)
            data = receive(conn) # TODO: check receive for security

            if self.chatLock.locked():
                # break out of message if other side closes
                if not data:
                    self.chatLock.release()
                    continue
                # throw away irrelevant messages
                if data['type'] != 'msg' and data['type'] != 'file':
                    logging.info("Chat already in progress, not listening to new clients")
                    continue
                logging.info("Received chat message: %s", data)
                cipher = AES.new(self.keyring[self.chatUID])
                msg = decrypt(data['data'], cipher)
                print ">>", msg
                continue

            if not data:
                continue

            logging.info("Received data: %s", data)
            if data['type'] == 'new conn':
                self.chatFlag = True
                # Another client is requesting a new connection
                nonce = random.randrange(1, 100000000) # <- this is checked later on (see below)
                self.sec_nonces[data['uid']] = nonce
                toSend = encrypt(pickle.dumps({'uid': data['uid'],
                                               'nonce': nonce}), self.cipher)
                logging.info("Sending information [%s] back to client", toSend)
                send(toSend, conn)
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
                send(nonceEnc, conn) # note: encrypted nonce is sent alone, not in a dict
                logging.info("Session nonce sent")
            
            elif data['type'] == 'conf':
                tmp_cipher = AES.new(self.keyring[data['uid']])
                nonce = decrypt(data['nonce'], tmp_cipher)
                if nonce != self.nonces[data['uid']] + 1:
                    logging("Confirmation nonce incorrect! connection rejected")
                    continue
                logging.info("Nonce confirmed. Starting messaging")
                # threading.Thread(target=self.receiver) # Start the listener that is supposed to return messages
                self.chatUID = data['uid']
                # Enter messaging state here
                print "Connected to client", data['uid'], " Press <ENTER> to continue"
                self.chat()

            elif data['type'] == 'clients':
                logging.info("Received new connection list from server")
                self.others = decrypt(data['data'], self.cipher)
                print "\nConnected clients updated:"
                for each in self.others:
                    print each
                print "Select a new client:\n:: ",

            else:
                logging.info("Message type not recognised")
                continue

            conn.close()

    # TODO: use this for the messaging state
    def chat(self):
        """ Used to send messages to the other client
        :return: True if the user indicates that they want to exit,
                 False if they want to chat to someone else"""
        # Stop the listener thread from processing anything else
        logging.info("Acquiring chat lock")
        self.chatLock.acquire()
        conn = connect(self.others[self.chatUID])
        if not conn:
            logging.info("Error connecting to other client for chat!")
            return False

        cli_cipher = AES.new(self.keyring[self.chatUID])
        m = ''
        logging.info("Entering messaging loop")
        while m != ':q':
            print "Enter a message (':q' to quit'):\n::",
            m = raw_input()
            if not self.chatLock.locked():
                print "Other client disconnected."
                break
            mEnc = encrypt(m, cli_cipher)
            toSend = {'type': 'msg',
                      'data': mEnc}
            send(toSend, conn)
        logging.info("Leaving chat")
        if self.chatLock.locked():
            self.chatLock.release()
