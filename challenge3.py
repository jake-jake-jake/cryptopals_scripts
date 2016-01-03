# This hex string has been xored against a single char.
# Write a script that finds the key and the plaintext.

import cryptotools as ct
from itertools import cycle

the_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

def cycle_xor(hex_string):
    byte_string = ct.hex_to_bytes(hex_string)
    found_match = False
    dictionary = ct.load_dictionary()
    for _ in range(256):
        xored = bytes(b ^ _ for b in list(byte_string))
        if ct.is_language(''.join([chr(b) for b in xored]), dictionary):
            print('Key: {}, ASCII: {}'.format(_, repr(xored)))
            found_match = True
    if not found_match:
        print('Unable to find match.')

print(cycle_xor(the_string))
