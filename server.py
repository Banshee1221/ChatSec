from socket import *
from threading import Thread
import logging
import sys


def clienthandler():
    """
    Handles incoming connections from the client applications.
    :return: True
    """
    _connection, _address = _soc.accept()
    logging.info("%s connected.", _address)
    if _address not in _cList:
        _cList.append(_connection)

    while True:
        incoming = _connection.recv(1024)
        if not incoming:
            break
        logging.info("Got data: %s from client %s", repr(incoming), _address)
        logging.info("Sending message %s to other clients", repr(incoming))
        messagepasser(_connection, incoming)
    return True

def messagepasser(client, msg):
    """
    Passes messages from the server through to the clients where the message does not originate.
    :param client: The specific client object that the message originates from
    :param msg: The message that needs to be passed through to the other clients
    :return: Boolean for successful or not
    """
    try:
        for all in _cList:
            if all != client:
                all.sendall(msg)
        return True
    except:
        return False



logging.basicConfig(stream=sys.stderr, level=logging.INFO)
_HOST = 'localhost'
_PORT = 8888
_cList = []

print "Initialising Server"
_soc = socket(AF_INET, SOCK_STREAM)
print "Binding Address and Port"
_soc.bind((_HOST, _PORT))
print ("Address: "+str(_HOST)+" | Port: "+str(_PORT))
_soc.listen(2)
print "Server Started\nListening..."

for i in range(2):
    Thread(target=clienthandler).start()

_soc.close()




