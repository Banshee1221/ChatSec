__author__ = 'Eugene'

import socket, random, pickle
from AES import *
from Crypto.Cipher import AES
from thread import *


class Client():

    clientID = 0
    sharedKey = 0
    IP = 0
    port = 0
    cli_sock = None
    listenOnly = False

    def __init__(self, ID, key, IP, port, listenOnly=False):
        self.clientID = ID
        self.sharedKey = key
        self.IP = IP
        self.port = port
        connectTo = str(raw_input("Who: "))
        self.authSrv(connectTo)
        self.listenOnly = listenOnly
        if listenOnly is True:



    def authSrv(self, who):
        self.cli_sock = socket.socket()
        self.cli_sock.connect((self.IP, self.port))
        nonce = random.randrange(1, 100000000)
        expiry = 50000
        packet = pickle.dumps([self.clientID, who, expiry, nonce])
        self.send(packet)
        recvEnc = self.cli_sock.recv(4096)
        print pickle.loads(recvEnc)
        decr = decrypt(pickle.loads(recvEnc), AES.new(self.sharedKey))
        print decr

    def chatListener(self):
        listenSoc = socket.socket()
        listenSoc.bind

    def send(self, msg):
        self.cli_sock.sendall(msg)



