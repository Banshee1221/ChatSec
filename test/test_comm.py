import sys
import logging
import cPickle
import socket
import pytest
sys.path.insert(0, 'src/')
from comm import *
# Number of tests: 8


test_addr = ('localhost', 0)
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
# logging doesn't display in test output

def setupListen():
    l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(test_addr)
    l.listen(5)
    return {'socket': l,
            'addr': l.getsockname()}


# connect
def test_connectSuccess():
    s = setupListen()
    assert connect(s['addr'])
    s['socket'].close()


def test_connectNoConnection():
    assert not connect(('localhost', 0))


def test_connectConnectionError():
    s = setupListen()
    s['socket'].close()
    assert not connect(s['addr'])


# send
def check_message_sent(msg):
    s = setupListen()
    soc = connect(s['addr'])
    assert send(msg, soc)

    s['socket'].close()


def test_sendStringEmpty():
    m = ""
    check_message_sent(m)


def test_sendString():
    m = "hello"
    check_message_sent(m)


def test_sendStringLong():
    m = "qwfpgjluy;[]'oienhdtsrazxcvbkm,./1234567890-="
    check_message_sent(m)


def test_sendStringOddChars():
    m = "`~!@#$%^&*()-=_+[]{}'|\\<>?,./"
    check_message_sent(m)


def test_sendDictEmpty():
    m = {}
    check_message_sent(m)


def test_sendDictStringToInt():
    m = {"a": 1, "b": 2, "c": 3}
    check_message_sent(m)


def test_sendDictStringToString():
    m = {"a": 'one', "b": 'two', "c": 'three'}
    check_message_sent(m)


def test_sendError():
    s = setupListen()
    soc = connect(s['addr'])
    s['socket'].close()
    assert not send('a sample message', soc)


# receive
def check_message_received(msg):
    s = setupListen()
    soc = connect(s['addr'])
    send(msg, soc)

    conn, addr = s['socket'].accept()
    recv = receive(conn)
    assert recv == msg
    assert type(recv) == type(msg)


def test_receiveStringEmpty():
    m = ""
    check_message_received(m)


def test_receiveString():
    m = "hello"
    check_message_received(m)


def test_receiveStringLong():
    m = "qwfpgjluy;[]'oienhdtsrazxcvbkm,./1234567890-="
    check_message_received(m)


def test_receiveStringOddChars():
    m = "`~!@#$%^&*()-=_+[]{}'|\\<>?,./"
    check_message_received(m)


def test_receiveDictEmpty():
    m = ""
    check_message_received(m)


def test_receiveDictStringToInt():
    m = {"a": 1, "b": 2, "c": 3}
    check_message_received(m)


def test_receiveDictStringToString():
    m = {"a": 'one', "b": 'two', "c": 'three'}
    check_message_received(m)


def test_receiveError():
    s = setupListen()
    soc = connect(s['addr'])
    send('a sample message', soc)

    conn, addr = s['socket'].accept()
    conn.close()
    assert not receive(conn)


# variable-length messages
def test_sendVarMessage():
    s = setupListen()
    soc = connect(s['addr'])
    f = open('test/files/small_file.txt', 'rb')
    toSend = f.read()
    f.close()
    assert send_var_message(toSend, soc)


def test_recVarMessage():
    s = setupListen()
    soc = connect(s['addr'])
    f = open('test/files/small_file.txt', 'rb')
    toSend = f.read()
    f.close()
    send_var_message(toSend, soc)

    conn, addr = s['socket'].accept()
    recv = recv_var_message(conn)
    assert toSend == recv
    assert type(toSend) == type(recv)
