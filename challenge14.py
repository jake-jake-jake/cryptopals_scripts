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
    con_bytes = PKCS7_pad(prefix + attacker_controlled + b64_bytes, 16)
    return ECB_encrypt(con_bytes, key)

def find_static_insertion(oracle):
    ''' Return insertion length that increases cipher by one blocksize.'''
    base_len = len(oracle(bytes(0)))
    # print('base_len:', base_len)
    for i in range(1, 17):
        # print('static_index_len:', len(oracle(bytes(i))))
        if len(oracle(bytes(i))) == base_len:
            # print('continuing')
            continue
        else:
            # print('index of %i increases len of oracle output' % i)
            return i
    else:
        raise ValueError('Blocksize of cipher is longer than 16.')

static_key = os.urandom(16)
static_prefix = os.urandom(randint(1, 50))
static_index = find_static_insertion(ECB_oracle)

print("static_key:", static_key)
print('static_prefix:', static_prefix)
print("static_prefix length:", len(static_prefix))
print('static_index:', static_index)
