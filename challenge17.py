#!/usr/bin/env python3

import binascii
import os 

from copy import deepcopy
from cryptotools import PKCS7_pad, PKCS7_unpad
from Crypto.Cipher import AES
from random import choice


def random_string_CBC(key):
    ''' CBC encrypt random string, return it with IV.'''
    strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
    instance_IV = os.urandom(16)
    plaintext = binascii.a2b_base64(choice(strings))
    cipher = AES.new(key, AES.MODE_CBC, instance_IV)
    return (cipher.encrypt(PKCS7_pad(plaintext, 16)), instance_IV)

def check_padding_CBC(ciphertext, instance_IV):
    ''' Return True if ciphertext has valid PKCS7 padding.'''
    cipher = AES.new(static_key, AES.MODE_CBC, instance_IV)
    decrypted = cipher.decrypt(ciphertext)
    try:
        message = PKCS7_unpad(decrypted)
    except ValueError:
        return False
    else:
        return True

def make_work_blocks(ciphertext, IV):
    ''' Return list of two block sections of CBC ciphertext.'''
    concatenated = IV + ciphertext
    print('DEBUG in make_work_blocks:\nlength of ciphtertext, blocks', len(ciphertext), len(concatenated))
    return [concatenated[i:i+32] for i in range(0, len(concatenated)-16, 16)]

def find_work_byte(target, IV, padding_oracle):
    ''' Change one byte of IV at a time to determine padding length and
        then return byte to work.'''
    index_byte = 0
    IV_copy = list(IV)
    while padding_oracle(target, bytes(IV_copy)):
        IV_copy[index_byte] = (IV_copy[index_byte] + 1) % 256
        index_byte += 1
    else:
        return index_byte - 1

def xor_previous_suffix(suffix):
    ''' Xor suffix bytes to prepare it to produce additional pad byte.'''
    first_xor = b''.join([bytes([a ^ b])
                    for a, b
                    in zip(suffix, bytes([len(suffix)] * len(suffix)))])
    return b''.join([bytes([a ^ b])
                    for a, b
                    in zip(first_xor, bytes([len(suffix) + 1] * len(suffix)))])

def decrypt_block_via_padding(target, IV, padding_oracle, work_byte = 15):
    ''' Decrypt a CBC block using an arbitrary IV and a padding oracle.'''
    prefix = IV[:work_byte-1]
    try: 
        suffix = IV[work_byte + 1:]
        suffix = xor_previous_suffix(suffix)
    except IndexError:
        suffix = b''
    possible_IVs = [prefix + bytes([b]) + suffix for b in range(256)]
    # for possible_IV in possible_IVs:
    # When this is done we want to return the final block of the IV, xored
    # against a full block of padding bytes, which will produce the plaintext.
    return None



def attack_CBC_via_padding_oracle(ciphertext, instance_IV):
    ''' Using instance_IV and padding oracle, decrypt ciphertext.'''
    work_blocks = make_work_blocks(ciphertext, instance_IV)
    # print(work_blocks)
    for block in work_blocks:
        target, IV = block[16:], block[:16]
        # Not the most elegant way to split up the block, but it works.
#        find_valid_padding_bytes(target, IV, check_padding_CBC)
    pass


static_key = os.urandom(16)
test_IV = os.urandom(16)
CBC_encrypt_cipher = AES.new(static_key, mode=2, IV=test_IV)
CBC_decrypt_cipher = AES.new(static_key, mode=2, IV=test_IV)
encrypted, this_IV = random_string_CBC(static_key)

admin_bytes = b'admin'
encrypted_admin = CBC_encrypt_cipher.encrypt(PKCS7_pad(admin_bytes, 16))
decrypted_admin = CBC_decrypt_cipher.decrypt(encrypted_admin)

print(decrypted_admin)
print(find_work_byte(encrypted_admin, test_IV, check_padding_CBC))