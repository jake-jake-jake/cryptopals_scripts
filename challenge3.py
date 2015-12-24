# This hex string has been xored against a single char.
# Write a script that finds the key and the plaintext.

import cryptotools as ct
from itertools import cycle

# if ct.is_language(''.join([chr(b) for b in xored]), dictionary):
the_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
dictionary = ct.load_dictionary()

def cycle_xor(hex_string):
    string_bytes = ct.hex_to_bytes(hex_string)
    list_bytes = [b for b in string_bytes]
    found_match = False
    for _ in range(256):
        xored = bytes(b ^ _ for b in list_bytes)
        if ct.check_chars(''.join([chr(b) for b in xored])):
            print('Key: {}, ASCII: {}'.format(_, repr(xored)))
            found_match = True
    if not found_match:
        print('Unable to find match.')

cycle_xor(the_string)
