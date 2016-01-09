#!/usr/bin/env python3.5

# Cryptopals Challenge 11

from collections import Counter
from Crypto.Cipher import AES
import os
from random import randint


def scramble_data(data):
    ''' Encrypt data using either CBC or ECB mode after pre/appending 5-10 bytes.'''
    EBC_or_CBC = randint(0,1)
    if EBC_or_CBC:
        return (ECB_encrypt(add_bytes(data)), EBC_or_CBC) 
    else:
        return (CBC_encrypt(add_bytes(data)), EBC_or_CBC) 

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def add_bytes(data):
    ''' Returns data with pre/suffix of 5-10 cryptographically random bytes.'''
    return (os.urandom(randint(5, 10)) + data + os.urandom(randint(5, 10)))
    
def CBC_encrypt(data):
    ''' Encrypt in AES CBC mode with random key and IV. '''
    CBC_cipher = AES.new(os.urandom(16), AES.MODE_CBC, os.urandom(16))
    return CBC_cipher.encrypt(PKCS7_pad(data, 16))

def ECB_encrypt(data):
    ''' Encrypt is AES ECB mode with random key. '''
    ECB_cipher = AES.new(os.urandom(16), AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def detect_AES_ECB_mode(ciphertext, blocksize = 16):
    ''' Return true if ciphertext encrypted in ECB mode. '''
    blocks = [ciphertext[x:x + blocksize] for x in range(0,len(ciphertext),blocksize)]
    if len(blocks) > len(set(blocks)):
        return True
    else:
        return False
    
# With controlled input (repetitive), this oracle begins to work when length of
# of ciphertext reaches 43, or there are guarunteed to be enough of the same bytes 
# to produce two full blocks of same byte after random insertion. 

data = b'A' * 43

results = []
for _ in range(100):
        cipher_data = scramble_data(data)
        ECB_detection = detect_AES_ECB_mode(cipher_data[0])
        results.append((ECB_detection, cipher_data[1]))

for ECB_detection, mode in results:
    if not ECB_detection == bool(mode):
        print('ECB detection failed. ') 

print('End of tests. No failures means success. ')



