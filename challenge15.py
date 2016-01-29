#!/usr/bin/env python3

# Challenge 14

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def PKCS7_unpad(data):
    ''' Remove PKCS7 padding.'''
    if data[-1] == 0 or not len(set(data[-data[-1]:])) == 1:
        raise ValueError('Invalid padding.')
    return data[:len(data)-data[-1]]

admin_invalid = b'yellowsubmarine\x02'
admin_valid = PKCS7_pad(b'admin', 16)
valid_sub = b'yellow submarin\x01'

print(PKCS7_unpad(admin_valid))
print(PKCS7_unpad(valid_sub))
print(PKCS7_unpad(admin_invalid))
