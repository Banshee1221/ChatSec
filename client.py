from socket import *
from threading import Thread

def connect():
    """
    Handles connections and sending messages to the server.
    :return: True
    """
    _input = ''
    while _input != 'exit':
        _input = str(raw_input())
        _soc.send(_input)
    return True


def receive():
    """
    Receives messages from the server and displays them.
    :return: True
    """
    while True:
        recv = _soc.recv(1024)
        if recv != '':
            print recv
    return True

_soc = socket()
_soc.connect(('localhost', 8888))
print "Connected."

t1 = Thread(target=connect).start()
t2 = Thread(target=receive).start()