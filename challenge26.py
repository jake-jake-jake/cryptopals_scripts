#!/usr/bin/env python3

# Challenge 26
# Functionally the same as challenge 16, but, this time using CTR mode rather 
# than CBC. Which I have to say is much easier to fuck with.


import os

from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptotools import bytes_xor


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


def bit_flip_CTR(CTR_oracle, target_bytes):
    ''' Flip bits in CBC cipher to produce target bytes at target block.'''
    insertion = bytes(16)
    work_cipher = CTR_oracle(insertion)
    # Assuming we know the point at which our insertion is entered into this;
    # it would be harder otherwise. We'll xor the cipher vs. our insertion.
    keystream_section = bytes_xor(work_cipher[32:48], insertion)
    # Now we xor the known section of keystream_section vs. our target_bytes.
    # This is simpler than CBC bitflipping. 
    second_insertion = bytes_xor(keystream_section, target_bytes)
    return work_cipher[:32] + second_insertion + work_cipher[48:]


static_key = os.urandom(16)
nonce = os.urandom(8)
insertion_goal = b';admin=true;p0wn'

bit_flipped_cipher = bit_flip_CTR(CTR_encrypt_oracle, insertion_goal)

print('Attack was a success:', find_admin(bit_flipped_cipher))
