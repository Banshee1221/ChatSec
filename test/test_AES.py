import pytest
from AES import *

testKey = "\xeb\xb9\x90!\xa3d\x889\t\xb7)?:\xc9(\xa0"

def test_padderEmpty():
	m = ''
	p = padder(m)
	assert padder(m) == m

def test_padderNormal():
	m = '1`g wuctre'
	p = padder(m)
	assert padder(m) == m+6*b'\x06'

def test_padderLong():
	m = 'av;l9 kj31cfpmcxhty3qkgh938q4g9q`*21-*/23+'
	p = padder(m)
	assert padder(m) == m+6*b'\x06'

def test_encryptionEmpty():
	m = ''
	c = AES.new(testKey)
	e = encrypt(m, c)
	d = decrypt(e, c)
	assert d == m

def test_encryptionNormal():
	m = 'Beeping test beep bloop'
	c = AES.new(testKey)
	e = encrypt(m, c)
	d = decrypt(e, c)
	assert d == m

def test_encryptionLong():
	m = '`~!@#$%^&*()-=_+\|[]{};":,./<>?1234567890'
	c = AES.new(testKey)
	e = encrypt(m, c)
	d = decrypt(e, c)
	assert d == m