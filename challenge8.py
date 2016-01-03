# challenge8.py

import cryptotools as ct

def test_for_AES_ECB(literal, block_length=16):
    subs = [literal[x:x+block_length] for x in range(0, len(literal), block_length)] 
    if len(subs) > len(set(subs)):
        return True
    else: 
        return False
    
with open('8.txt') as fo:
    encrypted = fo.read().split('\n')

line_number = 1
for hex_string in encrypted:
    byte_string = bytes.fromhex(hex_string)
    if test_for_AES_ECB(byte_string):
        print('Line {}:\n{}'.format(line_number, hex_string))
    line_number += 1



