import socket
import logging
import cPickle
import sys
import struct


def connect(address_pair):
    """
    Create 'client' type socket connected to the given address/port tuple
    :return: The created socket if the socket connects successfully,
    False otherwise"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(address_pair)
    except:
        error = sys.exc_info()[0]
        logging.info("Failed to set up socket - no connection to %s.",
                     address_pair)
        logging.info("Socket connection error: %s", error)
        return False
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # not necessary for client type sockets
    logging.info("Successfully created socket connected to %s", address_pair)
    return sock


def send(msg, sock):
    """
    Sends a serialized form of a data structure to the socket called 'sock'
    :return: True if all data was sent, False otherwise"""
    toSend = cPickle.dumps(msg)  # TODO: add compression
    try:
        ret = sock.sendall(toSend)  # Returns None ~ False when successful
    except:
        error = sys.exc_info()[0]
        logging.info("Error sending message: %s", error)
        ret = True
    return not ret


def receive(sock):
    """
    Receives a single message and displays it.
    :return: The reply sent over the socket. False if no reply or an error occurs.
    """
    rec = False
    try:
        rec = sock.recv(4096)
    except socket.error:
        logging.info("Error receiving message: %s", socket.error.strerror)
        return False
    if rec:
        logging.info("Received %s", str(rec).replace("\n", '').replace("\r", ''))
        msg = cPickle.loads(rec)
        logging.info("Loaded content: %s", msg)
        return msg
    return False


# Taken from http://stupidpythonideas.blogspot.com/2013/05/sockets-are-byte-streams-not-message.html
def send_var_message(data, sock):
    """
    Sends the length of the data to be sent, as well as the actual data.
    :return: None
    """
    pickle = cPickle.dumps(data)
    datalen = len(pickle)
    sock.sendall(struct.pack('!I', datalen))
    ret = sock.sendall(pickle)
    return not ret


def recv_var_message(sock):
    """
    Receives the length of the data to be sent from the server and passes it to recvall.
    :return: recvall
    """
    bufferlen = recvall(sock, 4)
    datalen, = struct.unpack('!I', bufferlen)
    return cPickle.loads(recvall(sock, datalen))


def recvall(sock, count):
    """
    Reads 'count' bytes from sock
    :return: None or the content of the data as a binary string
    """
    buff = b''
    while count:
        newbuff = sock.recv(count)
        if not newbuff:
            return None
        buff += newbuff
        count -= len(newbuff)
    return buff
