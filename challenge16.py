#!/usr/bin/env python3

# Challenge 16

import os
from Crypto.Cipher import AES

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def CBC_encrypt_oracle(byte_string):
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    cipher = AES.new(static_key, AES.MODE_CBC, static_IV)

    # clean the input string
    if b';' in byte_string or b'=' in byte_string:
        byte_string = byte_string.replace(b';', b'";"')
        byte_string = byte_string.replace(b'=', b'"="')
    return cipher.encrypt(PKCS7_pad(prefix + byte_string + suffix, 16))

def find_admin(byte_string):
    cipher = AES.new(static_key, AES.MODE_CBC, static_IV)
    decrypted = cipher.decrypt(ciphertext=byte_string)
    if b';admin=true;' in decrypted:
        return True 
    else:
        return False

def bit_flip_CBC(CBC_cipher, target_bytes, target_block, b_l=16):
    ''' Flip bits in CBC cipher to produce target bytes at target block.'''
    target_block = CBC_cipher[b_l * target_block: b_l * (target_block + 1)]
    # insert_block = [target_block ^ target_block]
    # return (CBC_cipher[: b_l * (target_block - 1)] + 
    #         insert_block + 
    #         CBC_cipher[b_l * target_block:])
    pass

test = b'this=this=admin;hahahaha'
static_key = os.urandom(16)
static_IV = os.urandom(16)


print(CBC_encrypt_oracle(test))
print(find_admin(CBC_encrypt_oracle(test)))
