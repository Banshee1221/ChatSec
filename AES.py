import cPickle
from Crypto.Cipher import AES
from Crypto import Random


def padder(message):
    """
    Ensured that the message (plaintext) is divisible by 16.
    :param message: The plaintext message to be encrypted
    :return: The plaintext message to be encrypted, with added padding
    """
    if len(message) % AES.block_size == 0:
        return message
    return message + ((AES.block_size-len(message) % AES.block_size) * b'\x00')

def unpadder(decr):
    """
    Undoes the padding applied to a message.
    :param decr: The decrypted message.
    :return: The message stripped of padding
    """
    l = decr.count(b'\x00')
    decr = decr[:len(decr) - l]
    return decr

def encrypt(plaintext, key):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    init = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, init)
    return cipher.encrypt(padder(cPickle.dumps(plaintext))) + init

def decrypt(ciphertext, key):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    init = ciphertext[-AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, init)
    return cPickle.loads(unpadder(cipher.decrypt(ciphertext[:-AES.block_size])))
