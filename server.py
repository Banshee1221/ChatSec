from socket import *
from threading import Thread
import logging
import sys
from Crypto.Cipher import AES
import cPickle


def clienthandler():
    """
    Handles incoming connections from the client applications.
    :return: True
    """
    conn, client = soc.accept()
    logging.info("%s connected.", client)
    incoming = conn.recv(1024)
    logging.info("Got data: || %s || from client %s", str(incoming).replace('\r', ' -line- ').replace('\n', ' -line- '), client)
    key = cPickle.loads(incoming)
    logging.info("Loaded serialized data from %s: %s", client, key)
    decrypted = ''
    for keys in cKeyList:
        logging.info("Generating new cipher with key %s", keys)
        clientCiph = AES.new(keys)
        logging.info("Generated new cipher for client.")
        decrypted = decrypt(clientCiph, key[1])
        if decrypted == str(key[0]):
            logging.info("Decrypted text: %s", decrypted)
            break
    if decrypted == '':
        logging.info("Unable to decrypt. Client rejected.")
        return False
    return True

def messagepasser(client, msg):
    """
    Passes messages from the server through to the clients where the message does not originate.
    :param client: The specific client object that the message originates from
    :param msg: The message that needs to be passed through to the other clients
    :return: Boolean for successful or not
    """
    try:
        for key in cKeyList:
            if key != client:
                key.sendall(msg)
        return True
    except:
        return False

def padder(message):
    """
    Ensured that the message (plaintext) is divisible by 32.
    :param message: The plaintext message to be encrypted
    :return: The plaintext message to be encrypted, with added padding
    """
    return message + ((32-len(message) % 32) * '{') # AES plain/cipher-text block size is 16 bytes, not 32 afaik

def encrypt(ciph, plaintext):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    return ciph.encrypt(padder(plaintext))

def decrypt(ciph, ciphertext):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    dec = ciph.decrypt(ciphertext)
    l = dec.count('{') # assuming '{' isn't used anywhere - maybe find another special char
    return dec[:len(dec) - l]

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

masterKey = b'\x5a\x00\x65\xcf\x47\x1a\x30\x3f\x61\x43\xb3\xa9\xab\x1a\x13\xe8\xb6\xfe\x8d\xb0\xff\x03\x85\xd1\x66' \
            b'\x83\xea\x9e\x60\xd4\xfe\xfa'
cipher = AES.new(masterKey)


cKeyList = [b'\x19\x17\xe3\x34\x07\xc2\x83\x66\xc8\xe3\xb9\x75\xb1\x7e\x73\x74\x58\x93\x12\x67\x6b\x90\x22\x9a\xdb\x4c\xe6\xe5\x85\x52\xe2\x23',
            b'\x3f\x45\x51\x43\xe7\x5d\x1e\x7f\xd6\x59\xde\xa5\x70\x23\x49\x6d\xa3\xbd\x9f\x2f\x89\x08\xd1\xe2\xac\x32\x64\x1c\xd8\x19\xd3\xe3', "o'H3}f23U>eQC1[WdrB90#wajZ@;DSc7"]

connectedClients = 0

print "Initialising Server"
soc = socket(AF_INET, SOCK_STREAM)

print "Binding Address and Port"
HOST = 'localhost'
PORT = 8888
soc.bind((HOST, PORT))

print ("Address: "+str(HOST)+" | Port: "+str(PORT))
soc.listen(2)

print "Server Started\nListening..."

# message = "test"
# enc = encrypt(cipher, message)
# print enc
# dec = decrypt(cipher, enc)
# print dec+"\n==================="

for i in range(2):
    Thread(target=clienthandler).start()

soc.close()




