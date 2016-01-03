# challenge5.py

from itertools import cycle

password = b'ICE'
plaintext = b'''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''

def xor_encrypt(pt, key):
    cm = zip(list(pt), cycle(list(key)))
    byte_string = bytes(x ^ y for x, y in cm)
    return byte_string.hex()

print(xor_encrypt(plaintext, password))
