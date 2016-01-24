#!/usr/bin/env python3

# Challenge 14

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def PKCS7_unpad(data):
    if not set(data[-1:]) == set(data[-data[-1]:]):
        raise ValueError('Invalid padding.')
    return data[:len(data)-data[-1]]
