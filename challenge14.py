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
    ''' Oracle prefixes random bytes to an attacker controlled variable
        then appends target bytes, pads and then encrypts. '''
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
    print('length of con_bytes', len(con_bytes))
    return ECB_encrypt(con_bytes, key)

def find_static_insertion(oracle):
    ''' Return insertion length that increases cipher by one blocksize.'''
    base_len = len(oracle(bytes(0)))
    print('base_len:', base_len)
    for i in range (16, 32):
        print('with insertion of ', i, 'length of', len(oracle(bytes(i))))
        if len(oracle(bytes(i + 1))) == base_len + 32:
            return i
    else: 
        raise ValueError('Unable to find static insertion. Block length longer than 16.')

def find_index_block(oracle, static_insertion_length):
    ''' Find index where variable insertion will be used to attack cipher.'''
    cipher = oracle(bytes(static_insertion_length + 32))
    for i in range(0, len(cipher)-16, 16):
        if cipher[i:i+16] == cipher[i+16:i+32]:
            return i
    else: 
        raise ValueError('Unable to verify ECB encryption.')


static_key = os.urandom(16)
static_prefix = os.urandom(randint(1, 50))
base_cipher_length = len(ECB_oracle(bytes(0)))
static_insertion = find_static_insertion(ECB_oracle)
block_index = find_index_block(ECB_oracle, static_insertion)

print('base_cipher_length:', base_cipher_length)
print("static_key:", static_key)
print('static_prefix:', static_prefix)
print("static_prefix length:", len(static_prefix))
print('static_insertion:', static_insertion)
print('prefix plus insertion length:', len(static_prefix) + static_insertion)
print('block_index:', block_index)
