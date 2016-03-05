#!/usr/bin/env python3

# Challenge 26
# Functionally the same as challenge 16, but, this time using CTR mode rather 
# than CBC.


import os

from Crypto.Cipher import AES
from Crypto.Util import Counter
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


def decrypt_AES_CTR(key, nonce, ciphertext, start_block=0):
    ctr = Counter.new(64, prefix=nonce, little_endian=True, initial_value=start_block)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


def encrypt_AES_CTR(key, nonce, plaintext, start_block=0):
    ctr = Counter.new(64, initial_value=start_block, little_endian=True, prefix=nonce)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)

def CTR_encrypt_oracle(byte_string):
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    # clean the input string
    if b';' in byte_string or b'=' in byte_string:
        byte_string = byte_string.replace(b';', b'";"')
        byte_string = byte_string.replace(b'=', b'"="')
    return encrypt_AES_CTR(static_key, nonce, prefix + byte_string + suffix)

def find_admin(byte_string):
    decrypted = decrypt_AES_CTR(static_key, nonce, byte_string)
    if b';admin=true;' in decrypted:
        return True 
    else:
        return False

def bit_flip_CTR(CBC_oracle, target_bytes, target_block, b_l=16):
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
nonce = os.urandom(8)
insertion_goal = b';admin=true;p0wn'

bit_flipped_cipher = bit_flip_CTR(CTR_encrypt_oracle, insertion_goal, 3)

print('Attack was a success:', find_admin(bit_flipped_cipher))
