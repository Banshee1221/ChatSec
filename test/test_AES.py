import pytest
import sys
sys.path.insert(0, 'src/')
from AES import *
# Number of tests: 6


testKey = "\xeb\xb9\x90!\xa3d\x889\t\xb7)?:\xc9(\xa0"

def test_padderEmpty():
	m = ''
	p = padder(m)
	assert padder(m) == m

# padder
def test_padderNormal():
	m = '1`g wuctre'
	p = padder(m)
	assert padder(m) == m+6*b'\x00'

def test_padderLong():
	m = 'av;l9 kj31cfpmcxhty3qkgh938q4g9q`*21-*/23+'
	p = padder(m)
	assert padder(m) == m+6*b'\x00'

# encryption - messages
def test_encryptionEmpty():
	m = ''
	e = encrypt(m, testKey)
	d = decrypt(e, testKey)
	assert d == m

def test_encryptionNormal():
	m = 'Beeping test beep bloop'
	e = encrypt(m, testKey)
	d = decrypt(e, testKey)
	assert d == m

def test_encryptionOddChars():
	m = '`~!@#$%^&*()-=_+\|[]{};":,./<>?1234567890'
	e = encrypt(m, testKey)
	d = decrypt(e, testKey)
	assert d == m

# encryption - files
def checkFile(f):
	e = encryptFile(f, testKey)
	d = decryptFile(e, testKey)
	fr = open(f, 'rb')
	x = fr.read()
	fr.close()
	assert d == x

def test_encryptFileEmpty():
	f = 'test/files/empty_file.txt'
	checkFile(f)

def test_encryptFileSmall():
	f = 'test/files/small_file.txt'
	checkFile(f)

def test_encryptFileBig():
	f = 'test/files/big_file.txt'
	checkFile(f)
