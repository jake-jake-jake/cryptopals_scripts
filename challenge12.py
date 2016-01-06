# Challenge 12

import binascii
from collections import Counter
from Crypto.Cipher import AES
import os

def prepend_bytes(target_bytes, insertion_byte = b'A', insertion_multiple = 32):
    ''' Prepends a number of bytes before target data; defaults to 32.'''
    insertion = insertion_byte * insertion_multiple
    return insertion + target_bytes
  
def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def ECB_encrypt(data, key):
    ''' Takes data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def detect_AES_ECB_mode(ciphertext, blocksize = 16):
    ''' Given a block of AES encrypted data, returns true if encrypted in ECB mode. '''
    blocks = [ciphertext[x:x + blocksize] for x in range(0,len(ciphertext),blocksize)]
    if len(blocks) > len(set(blocks)):
        return True
    else:
        return False

insert_byte = b'A'
b64_data = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                 aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                 dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                 YnkK'''

key = os.urandom(16)


def break_ECB_target(target, key):
    b64_bytes = binascii.a2b_base64(target)
    prepended_target = prepend_bytes(target_bytes=b64_bytes)
    encrypted_target = ECB_encrypt(prepended_target, key)
    print(encrypted_target)

print(break_ECB_target(b64_data, key=key))



