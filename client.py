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
    connClients = [] # list of dicts, each dict is a connected client

    def __init__(self, uid, key):
        self.UID = uid
        logging.info("Set UID: %s", uid)
        self.serverCipher = AES.new(key)
        logging.info("Created AES cipher using key %s.", key)
        logging.info("Running client startup\n================================")
        self.run()

    def connect(self, address_pair):
        """Create socket connected to the given address/port tuple
        :return: The created socket if the socket connects successfully,
        False otherwise"""
        sock = socket()
        try:
            sock.connect(address_pair)
        except error:
            logging.info("Failed to set up socket - no connection to %s.",
                    address_pair)
            return False
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        return sock

    def srvAuth(self):
        """Authenticates this client with the server.
        :return: True if authentication is successful, false otherwise."""
        uidEnc = self.encrypt(self.UID, self.serverCipher)
        authVar = [self.UID, uidEnc] # TODO: add enum for connection type
        self.send(authVar, self.serverSocket)
        serReply = self.receive(self.serverSocket)
        logging.info("Recieved server auth info: %s", serReply)
        if not serReply:
            return False
        self.connClients = eval(self.decrypt(serReply[0]))
        logging.info("Received client list from server: %s", self.connClients)
        return True

    def cliAuth(self, otherUID):
        """Authenticates this client with another connected user.
        :return: True if authentication is successful, false otherwise."""
        # Request session key from server
        UIDEnc = self.encrypt(self.UID, self.serverCipher)
        otherUIDEnc = self.encrypt(otherUID, self.serverCipher)
        authVar = [self.UID, UIDEnc, otherUIDEnc]
        self.send(authVar, self.serverSocket)
        serReply = self.receive(self.serverSocket)
        if not serReply:
            return False
        # Decrypt and pass on session key
        sKey = self.decrypt(serReply[0], self.serverCipher)
        logging.info("Got session key info from server: %s", serReply)

        # TODO: Complete this
        self.clientCipher = AES.new(sKey)
        UIDEnc2 = self.encrypt(self.UID, self.clientCipher)
        cliAuthVar = [self.UID, UIDEnc2, serReply[1]]
        self.send(cliAuthVar, self.clientSocket)
        cliReply = self.receive(self.clientSocket)
        print cliReply
        if not cliReply:
            return False
        return True

    def send(self, msg, sock):
        """Sends a list of data to the socket called 'sock'"""
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
            logging.info("Message from client: %s", decrypted)

    def padder(self, message):
        """
        Ensured that the message (plaintext) is divisible by 16.
        :param message: The plaintext message to be encrypted
        :return: The plaintext message to be encrypted, with added padding
        """
        return message + ((16-len(message) % 16) * '`')

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
        l = dec.count('`')
        return dec[:len(dec) - l]

    def run(self):
        # Connect to server
        logging.info("Connecting to server.")
        self.serverSocket = self.connect(('localhost', 8888))
        if not self.serverSocket:
            logging.info("Failed to connect to server")
            exit()
        logging.info("Established connection to server.")
        logging.info("Server socket connected? %s", not self.serverSocket=='')

        logging.info("Authenticating with server...")
        self.srvAuth()
        logging.info("Authenticated with server.")

        # TODO: start thread to listen to the server
        #self.serverSocket.listen(5)
        t1 = Thread(target=self.listen).start()

        # Connect to other client
        ruid = raw_input("Recipient uid: ")
        while ruid not in [x["uid"] for x in self.connClients]:
            print "Please choose another client."\
                    "Connected clients are:"
            for x in self.connClients:
                print x["uid"]
            logging.info("Connected clients: %s",
                    [x["uid"] for x in self.connClients])
            ruid = raw_input("Recipient uid: ")
            if ruid not in [x["uid"] for x in self.connClients]:
                print "Target client not connected."
                continue
            if eval(ruid) == self.UID:
                print "Cannot send messages to yourself. Get some friends."
                ruid = ''
                continue

            logging.info("Connecting to client.")
            targetAddress = ('')
            for x in self.connClients:
                if ruid == x["uid"]:
                    targetAddress = x["address"]
            self.clientSocket = self.connect(targetAddress)
            if not self.clientSocket:
                print "Connection to other client failed."
                ruid = ''
                continue
            logging.info("Established connection to client.")

            logging.info("Authenticating with client...")
            self.cliAuth(ruid)
            logging.info("Authenticated with client.")

        # Send messages
        msg = raw_input("Enter message (type '~e' to exit): ")
        while msg != '~e':
            # TODO: encrypt message
            self.send([msg], self.clientSocket)
            msg = raw_input("Enter message (type '~e' to exit): ")
