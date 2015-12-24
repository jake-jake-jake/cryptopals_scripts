# challenge8.py

import cryptotools as ct
from collections import Counter
from Crypto.Cipher import AES
from Crypto import Random

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_ECB, iv)

with open('8.txt') as fo:
	encrypted = fo.read()

enc_list = [ct.hex_to_bytes(x) for x in encrypted.split('\n')]

def test_for_AES_ECB(byte_string):
    subs = ct.slice_string_by_block(byte_string, 16)
    score = 0
    for sub in subs:
        for k in Counter(sub):
            score += Counter(sub)[k] - 1
    return score

scores = [(enc_list.index(x), test_for_AES_ECB(x)) for x in enc_list]
sorted_scores = sorted(scores, key = lambda x: x[1], reverse = True)[:5]

msg = cipher.decrypt(enc_list[132])
