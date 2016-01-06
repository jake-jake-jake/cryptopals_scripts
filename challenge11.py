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
    key = os.urandom(16)
    iv = os.urandom(16)
    padded_data = PKCS7_pad(data, 16)
    CBC_cipher = AES.new(key, AES.MODE_CBC, iv)
    return CBC_cipher.encrypt(padded_data)

def ECB_encrypt(data):
    key = os.urandom(16)
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    padded_data = PKCS7_pad(data, 16)
    return ECB_cipher.encrypt(padded_data)

def detect_AES_ECB_mode(ciphertext, blocksize = 16):
    ''' Given a block of AES encrypted data, returns true if encrypted in ECB mode. '''
    blocks = [ciphertext[x:x + blocksize] for x in range(0,len(ciphertext),blocksize)]
    if len(blocks) > len(set(blocks)):
        return True
    else:
        return False
    
# With controlled input (repetitive), this oracle begins to work when length of
# of ciphertext approaches 50, or there are 3 repeted key-length sequences of
# data. Does not work with plaintext data.

data = b'A' * 50
data2 = b'YELLOW SUBMARINE' * 3
data3 = b'"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?"'
data4 = data3 * 3
results = []

for _ in range(100):
        cipher_data = scramble_data(data)
        cipher_score = detect_AES_ECB_mode(cipher_data[0])
        results.append((cipher_score, cipher_data[1]))

print(sorted(results))



