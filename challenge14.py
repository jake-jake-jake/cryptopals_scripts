#!/usr/bin/env python3

# Challenge 14

import binascii
from Crypto.Cipher import AES
import os
from random import randint

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def ECB_encrypt(data, key):
    ''' Takes data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def ECB_oracle(attacker_controlled, prefix = None, key = None):
    ''' Oracle that encrypts a random prefix to an attacker controlled variable
        to a set of target bytes. '''
    b64_data = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                 aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                 dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                 YnkK'''
    b64_bytes = binascii.a2b_base64(b64_data)
    if prefix == None:
        prefix = static_prefix
    if key == None:
        key = static_key
    con_bytes = prefix + attacker_controlled + b64_bytes
    return ECB_encrypt(con_bytes, key)


static_key = os.urandom(16)
static_prefix = os.urandom(randint(1, 50))

print("static_key:", static_key)
print("static_prefix:", static_prefix)

for _ in range(1, 17):
    print (len(ECB_oracle(bytes(_))))
