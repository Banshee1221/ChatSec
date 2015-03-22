from socket import *
from random import random
import logging
import cPickle

def connect(address_pair):
	"""
	Create 'client' type socket connected to the given address/port tuple
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

def send(msg, sock):
	"""
	Sends a serialized form of a data structure to the socket called 'sock'
	:return: True if all data was sent, False otherwise"""
	toSend = cPickle.dumps(msg) # TODO: add compression
	try:
		ret = sock.sendall(toSend) # Returns None ~ False when successful
	except error:
		logging.info("Error sending message: %s", error.strerror)
		ret = True
	return not ret

def receive(sock):
	"""
	Receives a single message and displays it.
	:return: The reply sent over the socket. False if no reply.
	"""
	rec = False
	try:
		rec = sock.recv(1024)
	except error:
		logging.info("Error receiving message: %s", error.strerror)
		return False
	if rec:
		logging.info("Received %s", rec)
		msg = cPickle.loads(rec)
		logging.info("Loaded content: %s", msg)
		return msg
	return False