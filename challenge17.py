#!/usr/bin/env python3

import binascii
import os

from cryptotools import PKCS7_pad, PKCS7_unpad
from Crypto.Cipher import AES
from random import choice


def random_string_CBC(key):
    ''' Return random string CBC encypted, along with IV.'''
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


def controlled_string_CBC(key):
    ''' CBC encrypt control string string, return it with IV.'''
    instance_IV = os.urandom(16)
    plaintext = b'A' * 48
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
    return [concatenated[i:i+32] for i in range(0, len(concatenated)-16, 16)]


def find_work_byte(target, IV, padding_oracle):
    ''' Change one byte of IV at a time to determine padding length and
        then return index of next work_byte.'''
    index_byte = 0
    IV_copy = list(IV)
    while padding_oracle(target, bytes(IV_copy)):
        IV_copy[index_byte] = (IV_copy[index_byte] + 1) % 256
        index_byte += 1
    else:
        return index_byte - 2


def xor_previous_suffix(suffix):
    ''' Xor suffix bytes to prepare it to produce additional pad byte.'''
    first_xor = b''.join([bytes([a ^ b])
                    for a, b
                    in zip(suffix, bytes([len(suffix)] * len(suffix)))])
    return b''.join([bytes([a ^ b])
                    for a, b
                    in zip(first_xor, bytes([len(suffix) + 1] * len(suffix)))])


def make_suffix(IV, work_byte):
    ''' Process suffix bytes of IV insertion.'''
    # First round on each block will raise index error as work_byte is
    # last byte in IV.
    try: 
        suffix = IV[work_byte + 1:]
    except IndexError:
        return b''
    # if suffix (known bytes) is whole block, return block xored vs. padding
    if len(suffix) == 16:
        return b''.join([bytes([a ^ b])
                       for a, b
                       in zip(suffix, b'\x10' * 16)])
    # else prep suffix to make additional block of padding
    else:
        return xor_previous_suffix(suffix)


def CBC_pad_decrypt(target, IV, padding_oracle, work_byte = 15):
    ''' Decrypt a CBC block using an arbitrary IV and a padding oracle.'''
    prefix = IV[:work_byte]
    suffix = make_suffix(IV, work_byte)
    # if suffix (known blocks) are full block, return that value.
    if len(suffix) == 16:
        return suffix
    # else make all possible values for next byte of padding
    possible_IVs = [prefix + bytes([b]) + suffix for b in range(256)]
    for possible_IV in possible_IVs:
        if padding_oracle(target, possible_IV):
            index = find_work_byte(target, possible_IV, padding_oracle)
            return CBC_pad_decrypt(target, possible_IV, padding_oracle, index)
    else:
        print('No possible_IV passed oracle check. There is a problem.')
        return None


def attack_CBC_via_padding_oracle(ciphertext, instance_IV):
    ''' Using instance_IV and padding oracle, decrypt ciphertext.'''
    work_blocks = make_work_blocks(ciphertext, instance_IV)
    decrypted = []
    for block in work_blocks:
        target, IV = block[16:], block[:16]
        # Not the most elegant way to split up the block, but it works.
        modified_IV = CBC_pad_decrypt(target, IV, check_padding_CBC)
        # Modified_IV must be xored against the initial IV to recover the
        # plaintext.
        decrypted.append(b''.join([bytes([a ^ b])
                         for a,b 
                         in zip(modified_IV, IV)]))
    return b''.join(decrypted)


static_key = os.urandom(16)
encrypted, this_IV = random_string_CBC(static_key)

CBC_decryption = attack_CBC_via_padding_oracle(encrypted, this_IV)
print(PKCS7_unpad(CBC_decryption))
