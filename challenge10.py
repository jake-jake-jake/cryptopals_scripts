#!/usr/bin/env python3

# Challenge 10 

import binascii
from Crypto.Cipher import AES
from Crypto import Random

key = b'YELLOW SUBMARINE'
IV = b'0' * 16
cipher = AES.new(key, AES.MODE_CBC, IV)

with open('10.txt') as fo:
	encrypted = binascii.a2b_base64(fo.read())

print(cipher.decrypt(encrypted))

