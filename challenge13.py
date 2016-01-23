#!/usr/bin/env python3

from Crypto.Cipher import AES
import os



def parse_cookie(s):
    ''' Return dictionary from structured literal.'''
    return dict(x.split(b'=') for x in s.split(b'&'))

def profile_for(email=b'foo@bar.com', id_num=b'10', role=b'user'):
    ''' Create user Id and role from email.'''
    if b'&' in email or b'=' in email:
        raise ValueError('No "&" or "=" chars allowed in email.')
    return b'email=%b&id=%b&role=%b' % (email, id_num, role)

def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)

def ECB_encrypt(data, key):
    ''' Take data and key to produce AES ECB cipher.'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.encrypt(PKCS7_pad(data, 16))

def ECB_decrypt(cipher, key):
    ''' Decrypt ECB cipher using provided key'''
    ECB_cipher = AES.new(key, AES.MODE_ECB)
    return ECB_cipher.decrypt(PKCS7_pad(cipher, 16))

def cookie_oracle(email, key):
    ''' Return an ECB encrypted cookie from an email.'''
    return ECB_encrypt(PKCS7_pad(profile_for(email=email), 16), key)

# Debugging variables
dummy_morsels = b'foo=bar&baz=qux&zap=zazzle'
static_key = os.urandom(16)

# These are crafted to do the work. If our profile_for function stripped
# padding characters this method would not work.
insertion_block = PKCS7_pad(b'admin', 16)
print(insertion_block, len(insertion_block))
bait_email = b'xx@aol.com'
switch_email = b'xxxxxx@aol.com'

print(profile_for(bait_email + insertion_block))

# Create an insertion block to append to cookie, which should be 'admin' plus
# padding to mimic a final block of a cipher. Then create a prefix that should
# terminate just in time to accept our crafted 'admin' block.
attack_suffix = cookie_oracle((bait_email+insertion_block), static_key)[16:32]
print(ECB_decrypt(attack_suffix,static_key))
attack_prefix = cookie_oracle((switch_email), static_key)[:32]
print(ECB_decrypt(attack_prefix, static_key))

# Put pieces together.
finished_cookie = ECB_decrypt(attack_prefix + attack_suffix, static_key)

print(finished_cookie)

print(len(ECB_encrypt(b'email=xx@aol.com', static_key)))
