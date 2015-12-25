# Cryptopals Challenge 11

from Crypto.Cipher import AES
import os
from random import randint

def scramble_data(data):
	''' Randomly encrypt data using either CBC or ECB mode.'''
	expanded_data = add_bytes(data)
	EBC_or_CBC = randint(0,1)
	if EBC_or_CBC:
		return CBC_encrypt(expanded_data)
	else:
		return ECB_encrypt(expanded_data)

def pad_block(data, block_length, padding = b'\x04'):
	''' Return bytestring of specified block_length, using passed
		data and padding to do so. '''
	while len(data) < block_length:
		data += padding
	return data

def pad_data(data, block_length, padding = b'\x04'):
	data_blocks = [data[x:x + block_length] for x in range(0, len(data), block_length)]
	padded_data = []
	for block in data_blocks:
		if len(block) < block_length:
			padded_data.append(pad_block(block, block_length, padding))
		else:
							   padded_data.append(block)
	return b''.join(padded_data)

def add_bytes(data):
	''' Returns data with pre/suffix of 5-10 cryptographically random bytes.'''
	concatenated_bytes = []
	prepend_bytes = os.urandom(randint(5, 10))
	append_bytes = os.urandom(randint(5, 10))
	concatenated_bytes.append(prepend_bytes)
	concatenated_bytes.append(data)
	concatenated_bytes.append(append_bytes)
	return b''.join(concatenated_bytes)

def CBC_encrypt(data):
	key = os.urandom(16)
	iv = os.urandom(16)
	padded_data = pad_data(data, 16)
	CBC_cipher = AES.new(key, AES.MODE_CBC, iv)
	return CBC_cipher.encrypt(padded_data)

def ECB_encrypt(data):
	key = os.urandom(16)
	ECB_cipher = AES.new(key)
	padded_data = pad_data(data, 16)
	return ECB_cipher.encrypt(padded_data)

data = b'If you\'re not that familiar with crypto already, or if your familiarity comes mostly from things like Applied Cryptography, this fact may surprise you: most crypto is fatally broken. The systems we\'re relying on today that aren\'t known to be fatally broken are in a state of just waiting to be fatally broken. Nobody is sure that TLS 1.2 or SSH 2 or OTR are going to remain safe as designed.'


