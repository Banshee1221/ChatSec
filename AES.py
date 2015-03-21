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

def encrypt(plaintext, cipher):
    """
    Encrypts the plaintext message.
    :param plaintext: Plaintext message to be encrypted
    :return: Encrypted message based on the plaintext input
    """
    #serverCipher
    return cipher.encrypt(padder(pickle.dumps(plaintext)))

def decrypt(ciphertext, cipher):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :return: The decrypted plaintext message
    """
    dec = cipher.decrypt(ciphertext)
    l = dec.count(b'\x06')
    dec = dec[:len(dec) - l]
    return pickle.loads(dec)
