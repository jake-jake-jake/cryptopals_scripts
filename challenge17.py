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
    plaintext = choice(strings)
    cipher = AES.new(key, AES.MODE_CBC, instance_IV)
    return (cipher.encrypt(PKCS7_pad(bytes(plaintext, encoding='utf-8'), 16)), instance_IV)

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

static_key = os.urandom(16)

encrypted, this_IV = random_string_CBC(static_key)
print(check_padding_CBC(encrypted, this_IV))



