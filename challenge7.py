# challenge7.py

from Crypto.Cipher import AES
from Crypto import Random
import cryptotools as ct

with open('7.txt') as fo:
	encrypted = fo.read()

key = b'YELLOW SUBMARINE'

cipher = AES.new(key, AES.MODE_ECB)

encrypted_bytes = ct.base64_to_bytes(encrypted)
msg = cipher.decrypt(encrypted_bytes)

with open('7_decrypted.txt', 'w') as f:
    print(msg, file=f)
