#!/usr/bin/env python3

import binascii
import os 

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

def validate_single_padding_block(cipherblock, IV, padding_oracle):
    pass

def update_known_padding(pad):
    ''' Return bytes should produce one more valid byte of PKCS7 padding when
        tried against values for next byte in IV. '''
    return [bytes([a ^ b] for a,b in zip(pad, bytes([len(pad)]) * len(pad)))]


def find_valid_padding_bytes(work_block, padding_oracle, pad_bytes = []):
    ''' Iterate through IV bytes to find valid padding, beginning with last byte.'''
    print('DEBUG in find_valid_padding_bytes:\nlength of work_block', len(work_block))
    # Prefix length is one less than the length of pad_bytes. On first
    # run, this will be an empty list and so working on the last byte.
    prefix = work_block[:16-len(pad_bytes)-1]
    new_known_bytes = update_known_padding(pad_bytes)
    possible_IVs = [prefix + bytes([i]) + b''.join(reversed(new_known_bytes)) for i in range(256)]
    print('DEBUG in find_valid_padding_bytes:\n length of possibles', len(possible_IVs))
    for IV in possible_IVs:
        if padding_oracle(work_block[16:], IV):
            print(IV[:16-len(pad_bytes)-1])
            new_known_bytes.append(IV[:16-len(pad_bytes)-1])
            break
    else:
        print('DEBUG: Unable to find valid padding byte')
        return prefix + b''.join(reversed(new_known_bytes))

    # if len(work_list) > 1:
    #     print('DEBUG: Multiple possible valid padding bytes; must pass the choices to a function to find the valid \\x01 byte.')
    # elif len(work_list) == 1:
    #     pad_bytes.append(work_list[0])
    # else: 
    #     print('DEBUG: Unable to find valid padding byte.')
    if len(new_known_bytes) < 16:
        new_work_block = prefix + b''.join(reversed(new_known_bytes)) + work_block[16:]
        return find_valid_padding_bytes(new_work_block, padding_oracle, new_known_bytes)

    if len(passed_bytes) == 16:
        return b''.join(reversed(passed_bytes)) 


def decrypt_block(work_block, padding_oracle):
    ''' Working from padding_oracle output, decrypt second block of CBC block pair.'''
    pass

def attack_CBC_via_padding_oracle(ciphertext, instance_IV):
    ''' Using instance_IV and padding oracle, decrypt ciphertext.'''
    work_blocks = make_work_blocks(ciphertext, instance_IV)
    # print(work_blocks)
    for block in work_blocks:
        print('Trying block now:\n {}'.format(block))
        find_valid_padding_bytes(block, check_padding_CBC)


static_key = os.urandom(16)
encrypted, this_IV = random_string_CBC(static_key)

attack_CBC_via_padding_oracle(encrypted, this_IV)