from socket import *
from random import random
import logging
import cPickle

def connect(address_pair):
	"""Create 'client' type socket connected to the given address/port tuple
	:return: The created socket if the socket connects successfully,
	False otherwise"""
	sock = socket(AF_INET, SOCK_STREAM)
	try:
		sock.connect(address_pair)
	except error:
		logging.info("Failed to set up socket - no connection to %s.",
					 address_pair)
		logging.info("Socket connection error: %s", error.strerror)
		return False
	sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # not necessary for client type sockets
	logging.info("Successfully created socket connected to %s", address_pair)
	return sock

def sendPlain(msg, sock):
	"""Sends a list of data to the socket called 'sock'
	:return: The number of bytes sent"""
	toSend = cPickle.dumps(msg) # TODO: add compression
	return sock.sendall(toSend)

def sendEnc(msg, sock):
	"""Sends a list of data to the socket called 'sock'
	:return: The number of bytes sent"""
	toSend = cPickle.dumps(msg) # TODO: add compression
	return sock.sendall(toSend)

def receive(sock):
	"""Receives a single message and displays it.
	:return: The reply sent over the socket. False if no reply.
	"""
	rec = sock.recv(1024)
	if rec:
		logging.info("Received %s", rec)
		msg = cPickle.loads(rec)
		logging.info("Loaded content: %s", msg)
		return msg
	return False