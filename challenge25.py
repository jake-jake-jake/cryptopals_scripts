#!/usr/bin/env python3

# Break "random access read/write" AES CTR

# Back to CTR. Encrypt the '7_decrypted.txt' under CTR with a random key
# (for this exercise the key should be unknown to you, but hold on to it).

# Now, write the code that allows you to "seek" into the ciphertext, decrypt,
# and re-encrypt with different plaintext. Expose this as a function, like,
# "edit(ciphertext, key, offset, newtext)".

# Imagine the "edit" function was exposed to attackers by means of an API call
# that didn't reveal the key or the original plaintext; the attacker has the
# ciphertext and controls the offset and "new text".

# Recover the original plaintext. 

import os

from Crypto.Cipher import AES
from Crypto.Util import Counter


def decrypt_AES_CTR(key, nonce, ciphertext, start_block=0):
    ctr = Counter.new(64, prefix=nonce, little_endian=True, initial_value=start_block)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


def encrypt_AES_CTR(key, nonce, plaintext, start_block=0):
    ctr = Counter.new(64, initial_value=start_block, little_endian=True, prefix=nonce)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)


def edit_ciphertext(ciphertext, key, offset, newtext):
    ''' Edit ciphertext beginning at offset, inserting newtext there.'''
    block, index = divmod(offset, 16)
    previous_cipher_bytes = ciphertext[:block*16+index]
    garbage_bytes = bytes(index)
    data_to_encrypt = garbage_bytes + newtext
    new_cipher = encrypt_AES_CTR(key, nonce, data_to_encrypt, block)
    return previous_cipher_bytes + new_cipher[index:]

# Randomize nonce once the basic structure is working
nonce = os.urandom(8)
static_key = os.urandom(16)

