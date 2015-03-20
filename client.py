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
    serverCipher = '' # Cipher shared with server
    clientCipher = '' # Session cipher shared with client
    # TODO(optional): use keyring of ciphers instead of a single cipher
    clientSocket = '' # Send messages to client
    listenSocket = '' # Receive messages from client
    localAddress = () # Address pair for listenSocket
    connClients = [] # list of dicts, each dict is a connected client
    servKey = ''

    def __init__(self, uid, key):
        self.servKey = key
        self.UID = uid
        logging.info("Set UID: %s", uid)
        self.serverCipher = AES.new(key)
        logging.info("Created AES cipher using key %s.", key)
        self.localAddress = ("localhost", 61000+uid)
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
            logging.info("Socket connection error: %s", error.strerror)
            return False
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        return sock

    def srvAuth(self):
        """Authenticates this client with the server.
        :return: True if authentication is successful, false otherwise."""
        # Connect to server
        logging.info("Connecting to server.")
        srvSock = self.connect(('localhost', 8888))
        if not srvSock:
            logging.info("Failed to connect to server")
            exit()
        logging.info("Established connection to server.")
        logging.info("Server socket connected? %s", not srvSock=='')

        # Authenticate with server
        uidEnc = self.encrypt(self.UID, self.serverCipher)
        addrEnc = self.encrypt(self.localAddress, self.serverCipher)
        authVar = [self.UID, uidEnc, addrEnc] # TODO: add enum for connection type
        self.send(authVar, srvSock)

        # Confirm authentication
        serReply = self.receive(srvSock)
        logging.info("Recieved server auth info: %s", serReply)
        if not serReply:
            return False
        self.connClients = eval(str(self.decrypt(serReply[0])))
        logging.info("Received client list from server: %s", self.connClients)

        srvSock.close()
        return True

    def cliAuth(self, otherUID):
        """Authenticates this client with another connected user.
        :return: True if authentication is successful, false otherwise."""
        # Connect to server
        logging.info("Connecting to server.")
        srvSock = self.connect(('localhost', 8888))
        if not srvSock:
            logging.info("Failed to connect to server")
            exit()
        logging.info("Established connection to server.")
        logging.info("Server socket connected? %s", not srvSock=='')

        # Request session key from server
        UIDEnc = self.encrypt(self.UID, self.serverCipher)
        otherUIDEnc = self.encrypt(otherUID, self.serverCipher)
        authVar = [self.UID, UIDEnc, otherUIDEnc, random()]
        # random number here is a space-filler so that the server can distinguish
        # between a new client and one wanting to connect to another client. When
        # the ".*Auth" methods here send dicts instead of lists, we can remove
        # this field.
        logging.info("Sending request for session key.")
        self.send(authVar, srvSock)
        logging.info("Waiting for reply with session key.")
        serReply = self.receive(srvSock)
        if not serReply:
            logging.info("Got nothing from server")
            return False
        if len(serReply) == 2:
            logging.info("Target client not connected")
            print serReply[0]
            return False

        # Decrypt and pass on session key
        logging.info("Got session key info from server: %s", serReply)
        sKey = self.decrypt(serReply[0])
        logging.info("Decrypted session key. Creating cipher.")
        logging.info("Session key: %s with type %s", sKey, type(sKey))
        logging.info("Required key: %s", '\x5a\x00\x65\xcf\x47\x1a\x30\x3f\x61\x43\xb3\xa9\xab\x1a\x13\xe8\xb6\xfe\x8d\xb0\xff\x03\x85\xd1\x66\x83\xea\x9e\x60\xd4\xfe\xfa')
        logging.info("Server key : %s with type %s", self.servKey, type(self.servKey))
        logging.info("Session key is same length as server key? %s", len(sKey) == len(self.servKey))
        logging.info("Session key correctly decrypted? %s", sKey == b'\x5a\x00\x65\xcf\x47\x1a\x30\x3f\x61\x43\xb3\xa9\xab\x1a\x13\xe8\xb6\xfe\x8d\xb0\xff\x03\x85\xd1\x66\x83\xea\x9e\x60\xd4\xfe\xfa')
        self.clientCipher = AES.new(sKey)
        UIDEncOther = self.encrypt(self.UID, self.clientCipher)
        cliAuthVar = [self.UID, UIDEncOther, serReply[1]]
        self.send(cliAuthVar, self.clientSocket)

        cliReply = self.receive(self.clientSocket)
        # TODO: Complete this
        logging.info("Received reply from client: %s", cliReply)
        if not cliReply:
            logging.info("Client reply was empty.")
            return False
        dec = self.clientCipher.decrypt(cliReply[0])
        dec = dec[:len(dec) - dec.count(b'\x06')]
        if otherUID == dec:
            logging.info("Other client successfully authenticated.")
        srvSock.close()
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
        if rec:
            logging.info("Received %s from server/client.", rec)
            msg = cPickle.loads(rec)
            logging.info("Loaded content: %s", msg)
            return msg
        return False

    def listen(self): # Mirrors the server's clienthandler method
        """
        Receives all messages from the client for as long as the socket is open.
        """
        if not self.listenSocket:
            self.listenSocket = socket(AF_INET, SOCK_STREAM)
            self.listenSocket.bind(self.localAddress)
            self.listenSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.listenSocket.listen(5)
            logging.info("Client listening at address %s", self.localAddress)
        conn, addr = self.listenSocket.accept()
        logging.info("Connected to client at address %s", addr)
        # TODO: work from here
        incoming = self.receive(conn)
        if incoming:
            if len(incoming) == 4: # New connection
                logging.info("New connection from other client")
                sKey = self.decrypt(incoming[2])
                logging.info("Creating session cipher...")
                self.clientCipher = AES.new(sKey)
                logging.info("Authenticating other client")
                dec = self.clientCipher.decrypt(incoming[1])
                dec = int(dec[:len(dec) - dec.count(b'\x06')])
                if incoming[0] == dec: # Valid user
                    logging.info("Other client authenticated.")
                    reply = self.clientCipher.encrypt(self.padder(str(self.UID)))
                    self.send([reply], conn)
                    logging.info("Sent reply")
                else:
                    logging.info("Other client not authenticated. Got %s expected %s", dec, incoming[0])
                    logging.info("Incoming type: %s. Decrypted type: %s", type(incoming[0]), type(dec))
                    return False
            if len(incoming) == 2:
                logging.info("Message received from other client.")
                dec = self.clientCipher.decrypt(incoming[0])
                dec = dec[:len(dec) - dec.count(b'\x06')]

                print "\nMessage from client:", dec, "\n"

    def padder(self, message):
        """
        Ensured that the message (plaintext) is divisible by 16.
        :param message: The plaintext message to be encrypted
        :return: The plaintext message to be encrypted, with added padding
        """
        return message + ((16-len(message) % 16) * b'\x06')

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
        dec = self.serverCipher.decrypt(ciphertext)
        l = dec.count(b'\x06')
        return dec[:len(dec) - l]

    def run(self):
        # Authenticate with server
        logging.info("Authenticating with server...")
        self.srvAuth()
        logging.info("Authenticated with server.")

        # TODO: start thread to listen to the server
        t1 = Thread(target=self.listen).start()

        # Connect to other client
        ruid = ''
        while ruid not in [x["uid"] for x in self.connClients]:
            print "Connected clients are:"
            for x in self.connClients:
                print x["uid"]
            logging.info("Connected clients: %s",
                    [x["uid"] for x in self.connClients])
            try:
                ruid = int(raw_input("Recipient uid: "))
            #except (KeyboardInterrupt, SystemExit):
            #    exit()
            except ValueError:
                print "UID must be an integer."
                continue
            if ruid not in [x["uid"] for x in self.connClients]:
                print "Target client not connected."
                continue
            if ruid == self.UID:
                print "Cannot send messages to yourself. Get some friends."
                ruid = ''
                continue
            if ruid == 'e':
                exit()

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
            if not self.cliAuth(ruid):
                logging.info("Authentication with client failed.")
                ruid = ''
                continue
            logging.info("Authenticated with client.")

        # Send messages
        msg = raw_input("Enter message (type '~e' to exit): ")
        while msg != '~e':
            # TODO: encrypt message
            self.send([msg], self.clientSocket)
            msg = raw_input("Enter message (type '~e' to exit): ")
        exit()
