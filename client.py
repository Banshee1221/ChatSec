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
    sharedKey = 0
    IP = 0
    port = 0
    cli_sock = None
    listenOnly = False
    listenSock = ''
    others = {}
    listenIP = ''
    listenPORT = ''
    cipher = ''

    def __init__(self, ID, key, IP, port, listenOnly=False):
        self.clientID = ID
        self.sharedKey = key
        self.IP = IP
        self.port = port
        self.listenOnly = listenOnly
        # self.authSrv(connectTo)
        # start_new_thread(self.authSrv, connectTo)

        # Binding own port and connecting to server
        self.cipher = AES.new(self.sharedKey)
        start_new_thread(self.cliActListen, ())
        print "Self-listening started"
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cli_sock.connect((self.IP, self.port))
        print "Connecting to server with IP: " + str(self.IP) + ", PORT: " + str(self.port)

        self.identify()
        #start_new_thread(self.chatListener())

    def menu(self):
        print "Select one of:"
        for all in self.others:
            print all
        choice = str(raw_input(":: "))
        dictRet = self.others[choice]
        logging.info("Chosen %s", str(dictRet))
        self.authCli(choice, dictRet['IP'], dictRet['PORT'])

    def identify(self):
        id = self.clientID
        idEnc = encrypt(id, self.cipher)
        self.send(pickle.dumps((id, self.listenIP, self.listenPORT, idEnc)))
        self.others = pickle.loads(self.cli_sock.recv(1024))
        self.menu()

    def authSrv(self, who, encData):
        nonce = random.randrange(1, 100000000)
        expiry = 50000
        packet = pickle.dumps([self.clientID, who, expiry, nonce, encData])
        self.send(packet)
        recvEnc = self.cli_sock.recv(4096)
        logging.info("Received data from CA server: %s", pickle.loads(recvEnc))
        decr = decrypt(pickle.loads(recvEnc), AES.new(self.sharedKey))
        logging.info("Decoded information from the CA serv: %s", decr)

    def authCli(self, cli_id, cli_ip, cli_port):
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_sock.connect((cli_ip, cli_port))
        logging.info("Connected to client %s", cli_id)
        cli_sock.sendall(cli_id)
        logging.info("Sending the ID to the client")
        enc = cli_sock.recv(1024)
        cli_sock.close()
        logging.info("Info received from client: %s", enc.replace("\n", '').replace("\r", ''))
        self.authSrv(cli_id, enc)

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

    def send(self, msg):
        self.cli_sock.sendall(msg)

    def cliActListen(self):
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSock.bind(("127.0.0.1", 0))
        temp = self.listenSock.getsockname()
        print "Binding socket: " + str(temp)
        self.listenIP = temp[0]
        self.listenPORT = temp[1]
        self.listenSock.listen(5)
        conn, addr = self.listenSock.accept()
        logging.info("Connected from %s", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            logging.info("Received data: %s", data)
            if int(data) == self.clientID:
                nonce = random.randrange(1, 100000000)
                toSend = encrypt([data, nonce], self.cipher)
                logging.info("Sending information [%s] back to client", toSend)
                conn.sendall(toSend)
        conn.close()
