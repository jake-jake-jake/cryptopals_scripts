#!/usr/bin/env python3

# Challenge 16

import os
from Crypto.Cipher import AES

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def CBC_oracle(byte_string):
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    cipher = AES.new(static_key, AES.MODE_CBC, static_IV)

    # clean the input string
    if b';' in byte_string or b'=' in byte_string:
        byte_string = byte_string.replace(b';', b'%3B')
        byte_string = byte_string.replace(b'=', b'%3D')
    print('Debug:', prefix + byte_string + suffix)
    return cipher.encrypt(PKCS7_pad(prefix + byte_string + suffix, 16))

test = b'this=this=admin;hahahaha'
static_key = os.urandom(16)
static_IV = os.urandom(16)


print(CBC_oracle(test))
