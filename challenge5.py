# challenge5.py

import cryptotools as ct
from itertools import cycle

password = 'ICE'

plaintext = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''

def xor_encrypt(pt, key):
    cm = zip(list(pt), cycle(list(key)))
    cm = [ord(x) ^ ord(y) for x, y in cm]
    return ct.bytes_to_hex(bytes(cm))
