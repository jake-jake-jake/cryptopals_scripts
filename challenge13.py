#!/usr/bin/env python3

from Crypto.Cipher import AES
from http import cookies
import os



def parse_cookie(s):
    return s.replace('&', ';')

def profile_for(email='foo@bar.com', id_num=10, role='user'):
    if '&' in email or '=' in email:
        raise ValueError('No "&" or "=" chars allowed in email.')
    return 'email={}&id={}role={}'.format(email, id_num, role)

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def ECB_encrypt(data, key):
    ''' Take data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def ECB_decrypt(cipher, key):
    ''' Decript ECB cipher using provided key'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.decrypt(PKCS7_pad(cipher, 16))

key = os.urandom(16)
c = cookies.BaseCookie()

dummy_morsels = 'foo=bar&baz=qux&zap=zazzle'
dummy_email = 'aaaa@bbbbb.com'
dummy_profile = profile_for(dummy_email)
encrypted_dummy = ECB_encrypt(bytes(dummy_profile, encoding='utf-8'), key=key)

print('Dummy email length: {}'.format(len(dummy_email)))
print('Dummy profile length: {}'.format(len(dummy_profile)))
print('Dummy encryped cookie length: {}'.format(len(encrypted_dummy)))


