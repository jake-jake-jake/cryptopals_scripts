# challenge7.py

from Crypto.Cipher import AES
from Crypto import Random
import cryptotools as ct

with open('7.txt') as fo:
	encrypted = fo.read()

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)

cipher = AES.new(key, AES.MODE_ECB, iv)

encrypted_bytes = ct.base64_to_bytes(encrypted)
msg = cipher.decrypt(encrypted_bytes)
print(msg)




