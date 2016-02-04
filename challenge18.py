#!/usr/bin/env python3

# Matasano Cryptopals Challenge 17

from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

def decrypt_AES_CTR(key, nonce, ciphertext):
    ctr = Counter.new(64, prefix = nonce, little_endian=True, initial_value=0)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)

def encrypt_AES_CTR(key, nonce, plaintext):
    ctr = Counter.new(64, initial_value=0, little_endian=True, prefix=nonce)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)

static_key = b'YELLOW SUBMARINE'

nonce = struct.pack('<Q', 0)
encrypted = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

print(decrypt_AES_CTR(static_key, nonce, encrypted))