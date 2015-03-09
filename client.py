from socket import *
from threading import Thread
from Crypto.Cipher import AES
import cPickle

def connect():
    """
    Handles connections to the server.
    :return: True
    """
    keyEnc = encrypt(UID)
    print keyEnc
    authVar = [UID, keyEnc]
    print authVar
    toSend = cPickle.dumps(authVar)
    soc.send(toSend)
    print "Sent data"
    return True

def receive():
    """
    Receives messages from the server and displays them.
    :return: True
    """
    while True:
        recv = soc.recv(1024)
        if recv != '':
            print recv
    return True

def padder(message):
    """
    Ensured that the message (plaintext) is divisible by 32.
    :param message: The plaintext message to be encrypted
    :return: The plaintext message to be encrypted, with added padding
    """
    return message + ((32-len(message) % 32) * '{')

def encrypt(plaintext):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    cipher
    return cipher.encrypt(padder(str(plaintext)))

def decrypt(ciphertext):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    cipher
    dec = cipher.decrypt(ciphertext).decode('utf-8')
    l = dec.count('{')
    return dec[:len(dec) - l]


UID = 0

sharedKey = b'\x19\x17\xe3\x34\x07\xc2\x83\x66\xc8\xe3\xb9\x75\xb1\x7e\x73\x74\x58\x93\x12\x67\x6b\x90\x22\x9a\xdb\x4c\xe6\xe5\x85\x52\xe2\x23'
cipher = AES.new(sharedKey)

soc = socket()
soc.connect(('localhost', 8888))
print "Connected."

t1 = Thread(target=connect).start()
t2 = Thread(target=receive).start()