import pickle
from Crypto.Cipher import AES

def padder(message):
    """
    Ensured that the message (plaintext) is divisible by 16.
    :param message: The plaintext message to be encrypted
    :return: The plaintext message to be encrypted, with added padding
    """
    if len(message) % 16 == 0:
        return message
    return message + ((16-len(message) % 16) * b'\x06')

def unpadder(decr):
    """
    Undoes the padding applied to a message.
    :param decr: The decrypted message.
    :return: The message stripped of padding
    """
    l = decr.count(b'\x06')
    decr = decr[:len(decr) - l]
    return decr

def encrypt(plaintext, cipher):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    return cipher.encrypt(padder(pickle.dumps(plaintext)))

def decrypt(ciphertext, cipher):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    return pickle.loads(unpadder(cipher.decrypt(ciphertext)))
