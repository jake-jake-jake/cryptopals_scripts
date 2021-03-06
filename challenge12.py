#!/usr/bin/env python3

# Challenge 12

import binascii
from Crypto.Cipher import AES
import os

def prepend_bytes(target_bytes, insertion_byte = b'A', insertion_multiple = 32):
    ''' Prepends a number of bytes before target data; defaults to 32.'''
    insertion = insertion_byte * insertion_multiple
    return insertion + target_bytes

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def ECB_encrypt(data, key):
    ''' Takes data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def detect_AES_ECB_mode(ciphertext, blocksize = 16):
    ''' Given a block of AES encrypted data, returns true if encrypted in ECB mode. '''
    blocks = [ciphertext[x:x + blocksize] for x in range(0,len(ciphertext),blocksize)]
    if len(blocks) > len(set(blocks)):
        return True
    else:
        return False

def find_ECB_block_length(target, key):
    ''' Return likely blocklength of ECB mode cipher.'''
    for _ in range(1, 33):
        prepended_target = prepend_bytes(target, insertion_multiple = _)
        encrypted_target = ECB_encrypt(prepended_target, key)
        if detect_AES_ECB_mode(encrypted_target):
            print('Duplicate blocks of data with {} byte insertion, suggesting {} byte block length.'.format(_, _//2))
            return _//2
    else:
        print('Unable to confirm ECB mode.')
        return False

def create_byte_dict(insertion, key):
    return {ECB_encrypt(insertion + bytes([b]), key)[:16]: bytes([b]) for b in range(256)}


def byte_byte_ECB(target, key, b_l):
    plaintext = []
    while True:
        insertion = b'A' * (b_l - (len(plaintext) % b_l) - 1)
        b_i = len(plaintext) // b_l
        encrypted_target = ECB_encrypt(insertion + target, key)
        prepended_plaintext = insertion + b''.join(plaintext)
        byte_dict = create_byte_dict(prepended_plaintext[b_i * b_l:(b_i * b_l) + b_l], key)
        try:
            encrypted_block = encrypted_target[b_l * b_i:(b_i * b_l) + b_l]
            plaintext.append(byte_dict[encrypted_block])
        except:
            return b''.join(plaintext)

b64_data = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                 aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                 dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                 YnkK'''

b64_bytes = binascii.a2b_base64(b64_data)
static_key = os.urandom(16)

target_block_length = find_ECB_block_length(b64_bytes, static_key)
print(byte_byte_ECB(b64_bytes, static_key, target_block_length))
