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
        then appends target bytes and encrypts. '''
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

def find_insertion_and_index(oracle):
    ''' Returns insertion to zero random prefix to end of block
        and index of following block.'''
    for i in range (49):
        if verify_ECB(oracle, i):
            return (i - 32, verify_ECB(oracle, i))
    else:
        raise ValueError('Unable to find static insertion. Block length longer than 16.')

def verify_ECB(oracle, insertion):
    ''' Find index where variable insertion will be used to attack cipher.'''
    cipher = oracle(bytes(insertion))
    for i in range(0, len(cipher)-16, 16):
        if cipher[i:i+16] == cipher[i+16:i+32]:
            return i
    else: 
        return False

def create_byte_dict(oracle, insertion, b_i):
    ''' Return dictionary of all possible end bytes for block at index b_i.'''
    index = b_i * 16
    return {oracle(insertion + bytes([b]))[index: index + 16]: bytes([b]) 
            for b in range(256)}

def byte_byte_ECB(oracle, static_insert, static_ind):
    ''' Using determined static insertion and index, break ECB cipher byte by byte.'''
    plaintext = []
    while True:
        insert = bytes((15 - (len(plaintext) % 16) + static_insert))
        b_i = (len(plaintext) + static_ind) // 16    # block index
        prepended_plaintext = insert + b''.join(plaintext)
        encrypted_target = oracle(insert)
        byte_dict = create_byte_dict(oracle, prepended_plaintext, b_i)
        try:
            encrypted_block = encrypted_target[16 * b_i:(b_i * 16) + 16]
            plaintext.append(byte_dict[encrypted_block])
        except:
            return b''.join(plaintext)


static_key = os.urandom(16)
static_prefix = os.urandom(randint(1, 50))
base_cipher_length = len(ECB_oracle(bytes(0)))
static_insertion, static_index = find_insertion_and_index(ECB_oracle)

# print('base_cipher_length:', base_cipher_length)
# print('static_key:', static_key)
# print('static_prefix:', static_prefix)
# print('static_prefix length:', len(static_prefix))
# print('static_insertion:', static_insertion)
# print('static_index:', static_index)

print('target bytes:', byte_byte_ECB(ECB_oracle, static_insertion, static_index))
