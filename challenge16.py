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
    print('DEBUG: decrypted cipher:', decrypted)
    if b';admin=true;' in decrypted:
        return True 
    else:
        return False

def bit_flip_CBC(CBC_cipher, target_bytes, target_block, b_l=16):
    ''' Flip bits in CBC cipher to produce target bytes at target block.'''
    print('DEBUG: CBC_cipher before flipping, len\n', CBC_cipher, len(CBC_cipher))
    bytes_to_change = CBC_cipher[b_l * (target_block - 1): b_l * target_block]
    print('DEBUG: bytes_to_change: ', bytes_to_change)
    # print('DEBUG: Len bytes_to_change and target_bytes:', len(bytes_to_change), len(target_bytes))
    insert_block = bytes([a ^ b for a, b in zip(target_bytes, bytes_to_change)])
    print('DEBUG: insert_block, len:', insert_block, len(insert_block))
    flipped_cipher = CBC_cipher[:(target_block - 1) * b_l] + insert_block + CBC_cipher[target_block * b_l:]
    print('DEBUG: flipped_cipher, len\n', flipped_cipher, len(flipped_cipher))
    return flipped_cipher

test = b'this=this=admin;hahahaha'
static_key = os.urandom(16)
static_IV = os.urandom(16)
insertion_goal = b';admin=true;\x00\x00\x00\x00'
attack_insertion = b''

attack_cipher = CBC_encrypt_oracle(attack_insertion)
print('DEBUG: cipher before attack', find_admin(attack_cipher))
bit_flipped_cipher = bit_flip_CBC(attack_cipher, insertion_goal, 3)

print('Attack was a success:', find_admin(bit_flipped_cipher))
