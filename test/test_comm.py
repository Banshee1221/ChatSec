import pytest
import sys
import logging
from socket import *
from comm import *

test_addr = ('localhost', 8888)
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

def setupListen():
	l = socket(AF_INET, SOCK_STREAM)
	l.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	l.bind(test_addr)
	l.listen(5)
	return l

def test_connect():
	s = setupListen()
	assert connect(test_addr)
	s.close()

def test_sendPlainString():
	s = setupListen()
	m = "hello"
	soc = connect(test_addr)
	sendPlain(m, soc)

	conn, addr = s.accept()
	recv = receive(conn)
	assert recv == m
	s.close()

# def test_sendPlainDict():
# 	s = setupListen()
# 	m = {"a": 1, "b": 2, "c":3}
# 	soc = connect(test_addr)
# 	sendPlain(m, soc)

# 	conn, addr = s.accept()
# 	recv = receive(conn)
# 	assert recv == m
# 	s.close()

# def test_receive():
# 	# Getting address already in use error here
# 	# s = setupListen()
# 	# s.close()
# 	pass