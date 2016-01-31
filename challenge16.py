#!/usr/bin/env python3

# Challenge 16

import os
from Crypto.Cipher import AES
from cryptotools import bytes_xor

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def PKCS7_unpad(data):
    ''' Remove PKCS7 padding.'''
    if data[-1] == 0 or not len(set(data[-data[-1]:])) == 1:
        raise ValueError('Invalid padding.')
    return data[:len(data)-data[-1]]

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
    decrypted = PKCS7_unpad(cipher.decrypt(ciphertext=byte_string))
    if b';admin=true;' in decrypted:
        return True 
    else:
        return False

def bit_flip_CBC(CBC_oracle, target_bytes, target_block, b_l=16):
    ''' Flip bits in CBC cipher to produce target bytes at target block.'''
    insertion = bytes(16)
    work_cipher = CBC_oracle(insertion)
    # We know this is the plaintext; if we didn't, we would double our Z insertion.
    plaintext_to_be_flipped = b';comment2=%20lik'
    # The zero point that produced our known plaintext is this block; we need 
    # to treat it as the base from which we work.
    insertion_cipher_block = work_cipher[32:48]
    # Find the xor product of the target and known plaintext.
    bytes_to_produce_target = bytes_xor(plaintext_to_be_flipped, target_bytes)
    # Combine that product with the base cipherblock.
    flipped_bits = bytes_xor(insertion_cipher_block, bytes_to_produce_target)
    flipped_cipher = work_cipher[:32] + flipped_bits + work_cipher[48:]    
    return flipped_cipher

test = b'this=this=admin;hahahaha'
static_key = os.urandom(16)
static_IV = os.urandom(16)
insertion_goal = b';admin=true;p0wn'

bit_flipped_cipher = bit_flip_CBC(CBC_encrypt_oracle, insertion_goal, 3)

print('Attack was a success:', find_admin(bit_flipped_cipher))
