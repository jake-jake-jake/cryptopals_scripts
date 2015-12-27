# Challenge 12

from collections import Counter
from Crypto.Cipher import AES
import os


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

def ECB_encrypt(data, key):
    ''' Takes data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad_data(data, 16)
    return ECB_cipher.encrypt(padded_data)

def detect_AES_ECB_mode(ciphertext, blocksize = 16):
    ''' Given a block of AES encrypted data, returns true if encrypted in ECB mode. '''
    cipherslices = [ciphertext[x::blocksize] for x in range(blocksize)]
    score = 0
    correction = int(len(ciphertext) / (blocksize * 10)) + 1
    for slice in cipherslices:
        for k in Counter(slice):
            score += Counter(slice)[k] - correction
    if score >= blocksize:
        return True
    else:
        return False

data = b'A' * 48
key = os.urandom(16)

