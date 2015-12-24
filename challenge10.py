import itertools 
import binascii
from Crypto.Cipher import AES
from Crypto import Random

def cycle_xor(data, key):
	''' Xors data against a key, cycling on end of key. Key must be bytes'''
	cm = zip(list(data), itertools.cycle(list(key)))
	cm = [x ^ y for x, y in cm]
	return bytes(cm)

def pad_block(data, block_length, padding = b'\x04'):
	''' Return bytestring of specified block_length, using passed
		data and padding to do so. '''
	while len(data) < block_length:
		data += padding
	return data

def CBC_decrypt(data, block_length, key, IV, padding):
	''' Decrypts chained block cipher encrypted data. '''
	data_blocks = pad_data(data, block_length, padding)
	processed_data = []
	previous_block = IV
	data_blocks = data_blocks.reverse()

	for block in data_blocks:
		first_xor = cycle_xor(block, previous_block)
		second_xor = cycle_xor(first_xor, key)
		processed_data.append(second_xor)
		previous_block = second_xor

	return b''.join(processed_data.reverse())

def CBC_encrypt(data, block_length, key, IV, padding):
	''' Takes data of indeterminate length, chunks into blocks of block_length;
		using IV as 0th block in chain, proceeds to xor successive blocks with
		preceeding blocks as well as with key.'''
	data_blocks = pad_data(data, block_length, padding)
	previous_block = IV
	processed_data = []

	# with init variable set as first "previous block", proceed to xor each block of data by 
	# previous block and key, then store the result for use in next block
	for block in data_blocks:
			first_xor = cycle_xor(block, previous_block)
			second_xor = cycle_xor(first_xor, key)
			processed_data.append(second_xor)
			previous_block = second_xor

	return b''.join(processed_data)

def pad_data(data, block_length, padding):
	data_blocks = [data[x:x + block_length] for x in range(0, len(data), block_length)]
	padded_data = []
	for block in data_blocks:
		if len(block) < block_length:
			padded_data.append(pad_block(block, block_length, padding))
		else:
							   padded_data.append(block)
	return padded_data

key = b'YELLOW SUBMARINE'
padding = b'0'
IV = b'0' * 16
data = b'If you\'re not that familiar with crypto already, or if your familiarity comes mostly from things like Applied Cryptography, this fact may surprise you: most crypto is fatally broken. The systems we\'re relying on today that aren\'t known to be fatally broken are in a state of just waiting to be fatally broken. Nobody is sure that TLS 1.2 or SSH 2 or OTR are going to remain safe as designed.'
test = b'I am a fancy dolphin'

with open('10.txt') as fo:
	encrypted = binascii.a2b_base64(fo.read())


cipher = AES.new(key, AES.MODE_CBC, IV)

decrypted = cipher.decrypt(encrypted)
