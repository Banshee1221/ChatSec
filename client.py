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
    listenSock = ''
    others = ''

    def __init__(self, ID, key, IP, port, listenOnly=False):
        self.clientID = ID
        self.sharedKey = key
        self.IP = IP
        self.port = port
        connectTo = str(raw_input("Who: "))
        self.listenOnly = listenOnly
        #self.authSrv(connectTo)
        # start_new_thread(self.authSrv, connectTo)

        # Binding own port and connecting to server
        self.listenSock = socket.socket()
        self.listenSock.bind(("", 0))
        self.cli_sock = socket.socket()
        self.cli_sock.connect((self.IP, self.port))

        self.identify()
        start_new_thread(self.chatListener())

    def identify(self):
        self.send(pickle.dumps([self.clientID, self.listenSock.getsockname()]))


    def authSrv(self, who):
        nonce = random.randrange(1, 100000000)
        expiry = 50000
        packet = pickle.dumps([self.clientID, who, expiry, nonce])
        self.send(packet)
        recvEnc = self.cli_sock.recv(4096)
        print pickle.loads(recvEnc)
        decr = decrypt(pickle.loads(recvEnc), AES.new(self.sharedKey))
        print decr

    def authCli(self, cli_id, cli_ip, cli_port):
        pass

    def chatListener(self):
        while True:
            self.listenSock.listen(10)
            conn, addr = self.listenSock.accept()
            print conn.recv(4096)

    def send(self, msg):
        self.cli_sock.sendall(msg)