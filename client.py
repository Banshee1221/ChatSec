from socket import *
from threading import Thread
from Crypto.Cipher import AES
import cPickle
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

class Client:

    UID = ''
    sharedKey = '' #b'\x19\x17\xe3\x34\x07\xc2\x83\x66\xc8\xe3\xb9\x75\xb1\x7e\x73\x74\x58\x93\x12\x67\x6b\x90\x22\x9a\xdb\x4c\xe6\xe5\x85\x52\xe2\x23'
    cipher = ''
    soc = ''

    def __init__(self, uid, key):
        self.UID = uid
        logging.info("Set UID: %s", uid)
        self.sharedKey = key
        logging.info("Set sharedkey: %s", key)
        self.run()
        logging.info("Running client startup\n================================")

    def connect(self):
        """
        Handles connections to the server.
        :return: True
        """
        keyEnc = self.encrypt(self.UID)
        authVar = [self.UID, keyEnc]
        toSend = cPickle.dumps(authVar)
        self.soc.send(toSend)
        return True

    def receive(self):
        """
        Receives messages from the server and displays them.
        :return: True
        """
        while True:
            recv = self.soc.recv(1024)
            if recv != '':
                print recv
        return True

    def padder(self, message):
        """
        Ensured that the message (plaintext) is divisible by 32.
        :param message: The plaintext message to be encrypted
        :return: The plaintext message to be encrypted, with added padding
        """
        return message + ((16-len(message) % 16) * '{')

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext message.
        :param plaintext: Plaintext message to be encrypted
        :return: Encrypted message based on the plaintext input
        """
        self.cipher
        return self.cipher.encrypt(self.padder(str(plaintext)))

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext message.
        :param ciphertext: Ciphertext message based on the same cipher key
        :return: The decrypted plaintext message
        """
        self.cipher
        dec = self.cipher.decrypt(ciphertext).decode('utf-8')
        l = dec.count('{')
        return dec[:len(dec) - l]

    def run(self):
        self.soc = socket()
        logging.info("Setting up socket.")
        try:
            self.soc.connect(('localhost', 8888))
        except error:
            logging.info("Failed to connect to server")
            exit()
        logging.info("Established connection to server.")
        self.cipher = AES.new(self.sharedKey)
        logging.info("Established AES cipher.")

        t1 = Thread(target=self.connect).start()
        t2 = Thread(target=self.receive).start()