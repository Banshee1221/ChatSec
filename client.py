from socket import *
from threading import Thread
from Crypto.Cipher import AES
from random import random
import cPickle
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

class Client:

    UID = ''
    serverCipher = ''
    clientCipher = ''
    serverSocket = ''
    clientSocket = ''
    clients = {}
    connectedClients = []
    clientAddresses = {}

    def __init__(self, uid, key):
        self.UID = uid
        logging.info("Set UID: %s", uid)
        self.serverCipher = AES.new(key)
        logging.info("Created AES cipher using key %s.", key)
        logging.info("Running client startup\n================================")
        self.run()

    def connect(self, address_pair):
        """Connect socket to the given address/port tuple
        :return: True if the socket connects successfully, False otherwise"""
        sock = socket()
        try:
            sock.connect(address_pair)
        except error:
            logging.info("Failed to set up socket - no connection to %s.", address_pair)
            return False
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        return sock

    def srvAuth(self):
        """Authenticates this client with the server.
        :return: True if authentication is successful, false otherwise."""
        keyEnc = self.encrypt(self.UID, self.serverCipher)
        authVar = [self.UID, keyEnc] # TODO: add enum for connection type
        self.send(authVar, self.serverSocket)
        rec = self.receive(self.serverSocket)
        if not rec:
            return False
        connectedClients = self.decrypt(rec[0])
        clientAddresses = self.decrypt(rec[1])
        logging.info("Received client list from server: %s", connectedClients)
        logging.info("Received client addresses from server: %s", clientAddresses)
        return True

    def cliAuth(self, otherUID):
        """Authenticates this client with another connected user.
        :return: True if authentication is successful, false otherwise."""
        # Request session key from server
        UIDEnc = self.encrypt(self.UID, self.serverCipher)
        otherUIDEnc = self.encrypt(otherUID, self.serverCipher)
        authVar = [self.UID, UIDEnc, otherUIDEnc]
        self.send(authVar, self.serverSocket)
        rec = self.receive()
        if not rec:
            return False
        # Decrypt and pass on session key
        sKey = self.decrypt(rec[0], self.serverCipher)
        logging.info("Got session key info from server: %s", rec)

        # TODO: Complete this
        self.clientCipher = AES.new(sKey)
        UIDEnc2 = self.encrypt(self.UID, self.clientCipher)
        cliAuthVar = [self.UID, UIDEnc2, rec[1]]
        self.send(cliAuthVar, self.clientSocket)
        cliReply = self.receive(self.clientSocket)
        print cliReply
        if not cliReply:
            return False
        return True

    def send(self, msg, sock):
        """Sends a list of data to the server"""
        nonce = random() # Not sure if this is necessary for all messages
        msg.append(nonce) # Currently unused
        toSend = cPickle.dumps(msg) # TODO: add compression
        sock.send(toSend)

    def receive(self, sock):
        """
        Receives a single message and displays it.
        :return: The reply sent over the socket. False if no reply.
        """
        rec = sock.recv(1024)
        if rec != '':
            logging.info("Received %s from server.", rec)
            msg = cPickle.loads(rec)
            logging.info("Loaded content: %s", msg)
            return msg
        return False

    def listen(self):
        """
        Receives all messages from the client for as long as the socket is open.
        """
        if self.clientSocket:
            incoming = self.receive(self.clientSocket)
            decrypted = self.decrypt(incoming)
            logging.info("Received %s from client.", decrypted)

    def padder(self, message):
        """
        Ensured that the message (plaintext) is divisible by 16.
        :param message: The plaintext message to be encrypted
        :return: The plaintext message to be encrypted, with added padding
        """
        return message + ((16-len(message) % 16) * '{')

    def encrypt(self, plaintext, cipher):
        """
        Encrypts the plaintext message.
        :param plaintext: Plaintext message to be encrypted
        :return: Encrypted message based on the plaintext input
        """
        #self.serverCipher
        return cipher.encrypt(self.padder(str(plaintext)))

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext message.
        :param ciphertext: Ciphertext message based on the same cipher key
        :return: The decrypted plaintext message
        """
        self.serverCipher
        logging.info("Ciphertext length mod 16: %d", len(ciphertext)%16)
        dec = self.serverCipher.decrypt(ciphertext).decode('utf-8')
        l = dec.count('{')
        return dec[:len(dec) - l]

    def run(self):
        # Connect to server
        logging.info("Connecting to server.")
        self.serverSocket = self.connect(('localhost', 8888))
        if not self.serverSocket:
            logging.info("Failed to connect to server")
            exit()
        logging.info("Established connection to server.")
        logging.info("Server socket: %s", self.serverSocket=='')

        logging.info("Authenticating with server...")
        self.srvAuth()
        logging.info("Authenticated with server.")

        # TODO: start thread to listen to the server
        #self.serverSocket.listen(5)
        t1 = Thread(target=self.listen).start()

        # Connect to other client
        ruid = raw_input("Recipient uid: ")
        while ruid not in self.clients:
            print "Target client not connected. Choose another client."
            ruid = raw_input("Recipient uid: ")

        logging.info("Connecting to client.")
        self.connect(self.clientSocket, self.clients[ruid]["address"])
        logging.info("Established connection to client.")

        logging.info("Authenticating with client...")
        self.cliAuth(ruid)
        logging.info("Authenticated with client.")

        # Send messages
        msg = ''
        while msg != 'exit':
            msg = raw_input("Enter message: ")
            # TODO: encrypt message
            self.send([].append(msg), self.clientSocket)
