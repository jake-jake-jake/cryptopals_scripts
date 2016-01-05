#!/usr/bin/env python3

# Implement PKCS7 padding

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    missing_bytes = block_length - (len(data) % block_length)
    return (data + bytes([missing_bytes])*missing_bytes)

test_string = b'YELLOW SUBMARINE'
test_block_len = 20

# for _ in range(2,21):
#     print(PKCS7_pad(test_string, _))

print(PKCS7_pad(test_string, test_block_len))


