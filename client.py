__author__ = 'Eugene'

import socket
import random
import pickle
import logging
import sys
from thread import *
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
    listenSock = '' # server socket for client listening to incoming client connections
    listenIP = ''
    listenPORT = ''

    def __init__(self, ID, key, IP, port, listenOnly=False):
        self.clientID = ID
        self.sharedKey = key
        self.cipher = AES.new(self.sharedKey)
        self.IP = IP
        self.port = port
        self.listenOnly = listenOnly
        # self.authSrv(connectTo)
        # start_new_thread(self.authSrv, connectTo)
        self.run()
        
    def run(self):
        # Binding own port and connecting to server
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Connecting to server with IP: " + str(self.IP) + ", PORT: " + str(self.port)
        self.cli_sock.connect((self.IP, self.port))
        print "Success! Connected to server"
        
        # ensure that listenSock is set up before identify sends socket info to the server
        self.setupListen() 
        start_new_thread(self.listenToClients, ())
        print "Self-listening started"
        
        self.identify()
        self.menu()

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
            print "Select one of:"
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
        self.authCli(choice, dictRet['IP'], dictRet['PORT'])

    def authCli(self, cli_id, cli_ip, cli_port):
        # Send initial request to other client
        tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_sock.connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        tmp_sock.sendall(cli_id)
        logging.info("Sending the ID to the client")
        enc = tmp_sock.recv(1024)
        tmp_sock.close()
        logging.info("Info received from client: %s", enc.replace("\n", '').replace("\r", ''))

        # Pass on package to the server, then send reply (with session key)
        # to the other client
        package = self.authSrv(cli_id, enc)
        

        logging.info("Reached the end")

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
        decr = pickle.loads(decrypt(recvEnc, AES.new(self.sharedKey)))
        logging.info("Decoded information from the CA serv: %s", decr)
        if decr['otheruid'] != who or decr['nonce'] != nonce:
            logging.info("Invalid reply from server")
            return False
        self.keyring[who] = decr['sKey']

        return decr['enc']

    def send(self, msg):
        self.cli_sock.sendall(msg)

    def setupListen(self):
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # <- must be called before bind
        self.listenSock.bind(("127.0.0.1", 0))
        temp = self.listenSock.getsockname()
        print "Binding socket: " + str(temp)
        self.listenIP = temp[0]
        self.listenPORT = temp[1]
        self.listenSock.listen(5)        

    def listenToClients(self):
        conn, addr = self.listenSock.accept()
        logging.info("Connected with %s", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            logging.info("Received data: %s", data)
            if data == self.clientID:
                nonce = random.randrange(1, 100000000)
                toSend = encrypt(pickle.dumps({'otheruid': data, 'nonce': nonce}), self.cipher)
                logging.info("Sending information [%s] back to client", toSend)
                conn.sendall(toSend)
        conn.close()
    
    # TODO: Combine this with listenToClients
    def chatListener(self):
        logging.info('Listening for info')
        conn, addr = self.listenSock.accept()
        logging.info('Received connection: %s, address: %s', conn, addr)
        while True:
            data = conn.recv(4096)
            if not data:
                break
        conn.close()
        return data