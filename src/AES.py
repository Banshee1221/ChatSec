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
    :param key: Key used to encrypt the plaintext
    :return: Encrypted message based on the plaintext input
    """
    init = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, init)
    return cipher.encrypt(padder(cPickle.dumps(plaintext))) + init

def decrypt(ciphertext, key):
    """
    Decrypts the ciphertext message.
    :param ciphertext: Ciphertext message based on the same cipher key
    :param key: Key used to encrypt the plaintext
    :return: The decrypted plaintext message
    """
    init = ciphertext[-AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, init)
    return cPickle.loads(unpadder(cipher.decrypt(ciphertext[:-AES.block_size])))

def encryptFile(filename, key):
    """
    Encrypts a file with a given key.
    :param filename: Path to the file that needs to be encrypted
    :param key: Key used to encrypt the file
    :return: Encrypted file as a string
    """
    fr = open(filename, 'rb')
    plaintext = fr.read()
    fr.close()
    payload = {'filename': filename,
               'data': plaintext}
    return encrypt(payload, key)

def decryptFile(ciphertext, key):
    """
    Decrypts a string with a given key. Writes the plaintext to the out/ folder
    :param ciphertext: Ciphertext to be decrypted
    :param key: Key used to decrypt the file
    :return: Decrypted file as a dict
    """
    payload = decrypt(ciphertext, key)
    fw = open('out/'+payload['filename'][payload['filename'].rfind('/')+1:],
              'wb')
    fw.write(payload['data'])
    fw.close()
    return payload