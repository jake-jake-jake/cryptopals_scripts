# This hex string has been xored against a single char.
# Write a script that finds the key and the plaintext.

import cryptotools as ct
from itertools import cycle

def cycle_xor(hex_string):
    byte_string = ct.hex_to_bytes(hex_string)
    found_match = False
    dictionary = ct.load_dictionary()
    for _ in range(256):
        xored = bytes(b ^ _ for b in list(byte_string))
        if ct.is_language(''.join([chr(b) for b in xored]), dictionary):
            print('Hex String: {} \nKey: "{}" \nASCII: {}'.format(hex_string, chr(_), xored.decode()))
            found_match = True
    if not found_match:
        # I had this print out each line in the loaded .txt, but that made output messy. Now passing.
        pass
    

with open('4.txt') as h_s:
    h_s = h_s.read().split('\n')
    for line in h_s:
        try:
            cycle_xor(line)
        except:
            print('Error in processing this line: \n{}'.format(line))




