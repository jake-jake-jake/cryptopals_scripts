# This hex string has been xored against a single char.
# Write a script that finds the key and the plaintext.

import cryptotools as ct
from itertools import cycle

dictionary = ct.load_dictionary()

def cycle_xor(hex_string):
    string_bytes = ct.hex_to_bytes(hex_string)
    list_bytes = [b for b in string_bytes]
    found_match = False
    for _ in range(256):
        xored = bytes(b ^ _ for b in list_bytes)
        if ct.is_language(''.join([chr(b) for b in xored]), dictionary):
            print('String: {} \n Key: {}, ASCII: {}'.format(hex_string, _, repr(xored)))
            found_match = True
    if not found_match:
        print('Unable to find match for string: \n{}'.format(hex_string))
    

with open('4.txt') as h_s:
    h_s = h_s.read().split('\n')
    for line in h_s:
        try:
            cycle_xor(line)
        except:
            print('Error in processing this line: \n{}'.format(line))




