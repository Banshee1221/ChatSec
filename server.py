from socket import *
from threading import Thread
from random import random
from Crypto.Cipher import AES
import logging
import sys
import cPickle


def clienthandler(): # Mirrors the client's listen method
    """
    Handles incoming connections from the client applications.
    :return: True
    """
    # Load data from client
    conn, addr_pair = soc.accept()
    logging.info("%s connected.", addr_pair)
    msg = receive(conn)
    # TODO: check nonce is fresh?

    # Find cipher for user
    keyToUse = cKeyList[msg[0] - 1] # TODO: handle invalid uids
    logging.info("Generating new cipher with key %s", keyToUse)
    clientCiph = AES.new(keyToUse)
    logging.info("Generated new cipher for client.")

    # Authenticate client
    decryptedUID = decrypt(clientCiph, msg[1])
    if decryptedUID == str(msg[0]):
        logging.info("Decrypted UID: %s", decryptedUID)
    else:
        logging.info("Unable to authenticate. Client rejected.")
        return False

    # Handle message from client
    # TODO: add message field to distinguish between message types.
    # (Using message length for now)
    if len(msg) == 4: # server authentication
        logging.info("Client-server auth...")
        # Add new client to connected clients list
        decryptedAddress = decrypt(clientCiph, msg[2])
        if decryptedUID not in connectedClients:
            newclient = {"uid":int(decryptedUID), "address":eval(decryptedAddress)}
            logging.info("New address: %s", eval(decryptedAddress))
            connectedClients.append(newclient)
        # Send list of connected clients to client
        # TODO: make this a broadcast to all clients
        # logging.info("Broadcasting connected clients")
        # for client in connectedClients:
        #    key = cKeyList[client["uid"] - 1]
        #    clientCiph = AES.new(key) # note: duplicate key creation
        #    connListEnc = encrypt(clientCiph, connectedClients)
        #    out = [connListEnc]
        #    logging.info("Encrypted connectedClients with client cipher %s\n" \
        #            "Sending to client %s", out, client["uid"])
        connListEnc = encrypt(clientCiph, connectedClients)
        out = [connListEnc]
        logging.info("Encrypted connectedClients with client cipher %s\n" \
                "Sending to client %s", out, eval(decryptedUID))
        send(out, conn)
        logging.info("Connected clients list sent")
    elif len(msg) == 5: #other client authentication
        # Create the other client's cipher
        logging.info("Client-client keygen...")
        otherUID = int(decrypt(clientCiph, msg[2]))
        if otherUID not in [x["uid"] for x in connectedClients]:
            logging.info("Target client not connected")
            m = ["Target client not connected"]
            send(m, conn)
            return False
        otherKey = cKeyList[otherUID - 1]
        otherCiph = AES.new(otherKey)

        logging.info("Generating session key...")
        secKey = masterKey # TODO: dynamically generate this!!!1!

        logging.info("Encrypting session key")
        secKeyEnc = encrypt(clientCiph, secKey)
        otherSecKeyEnc = encrypt(otherCiph, secKey)

        logging.info("Sending session key")
        pack = [secKeyEnc, otherSecKeyEnc]
        send(pack, conn)
        logging.info("Session key sent")

    return True

def send(msg, socket):
    """Sends a message to the given socket"""
    nonce = random() # Not sure if this is necessary for all messages
    msg.append(nonce) # Currently unused
    toSend = cPickle.dumps(msg) # TODO: add compression
    socket.send(toSend)

def receive(socket):
    """
    Receives a single message and displays it.
    :return: The reply sent over the socket. False if no reply.
    """
    rec = socket.recv(1024)
    if rec != '':
        logging.info("Received %s from client.", rec)
        msg = cPickle.loads(rec)
        logging.info("Loaded serialized data: %s", msg)
        return msg
    return False

def padder(message):
    """
    Ensured that the message (plaintext) is divisible by 32.
    :param message: The plaintext message to be encrypted
    :return: The plaintext message to be encrypted, with added padding
    """
    return message + ((16-len(message) % 16) * '`')

def encrypt(ciph, plaintext):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    return ciph.encrypt(padder(str(plaintext)))

def decrypt(ciph, ciphertext):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    dec = ciph.decrypt(ciphertext)
    l = dec.count('`') # assuming '`' isn't used anywhere - maybe find another special char
    return dec[:len(dec) - l]

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

masterKey = b'\x5a\x00\x65\xcf\x47\x1a\x30\x3f\x61\x43\xb3\xa9\xab\x1a\x13\xe8\xb6\xfe\x8d\xb0\xff\x03\x85\xd1\x66\x83\xea\x9e\x60\xd4\xfe\xfa'
cipher = AES.new(masterKey)


cKeyList = [b'\x19\x17\xe3\x34\x07\xc2\x83\x66\xc8\xe3\xb9\x75\xb1\x7e\x73\x74\x58\x93\x12\x67\x6b\x90\x22\x9a\xdb\x4c\xe6\xe5\x85\x52\xe2\x23',
            b'\x3f\x45\x51\x43\xe7\x5d\x1e\x7f\xd6\x59\xde\xa5\x70\x23\x49\x6d\xa3\xbd\x9f\x2f\x89\x08\xd1\xe2\xac\x32\x64\x1c\xd8\x19\xd3\xe3', "o'H3}f23U>eQC1[WdrB90#wajZ@;DSc7"]

connectedClients = []

print "Initialising Server"
soc = socket(AF_INET, SOCK_STREAM)

print "Binding Address and Port"
HOST = 'localhost'
PORT = 8888
soc.bind((HOST, PORT))

print ("Address: "+str(HOST)+" | Port: "+str(PORT))
soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
soc.listen(5)

print "Server Started\nListening..."

# message = "test"
# enc = encrypt(cipher, message)
# print enc
# dec = decrypt(cipher, enc)
# print dec+"\n==================="

#for i in range(5):
#    Thread(target=clienthandler).start()
#Thread(target=clienthandler).start()
while 1:
    clienthandler()

soc.close() # we should maybe call shutdown(1) before close: https://docs.python.org/2/howto/sockets.html#disconnecting
