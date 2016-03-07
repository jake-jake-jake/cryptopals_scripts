#!/usr/bin/env python3

# Recover the key from a CBC cipher when the key is used as an IV.
# http://cryptopals.com/sets/4/challenges/27/

import os
from Crypto.Cipher import AES
from cryptotools import bytes_xor, PKCS7_pad, PKCS7_unpad


# RECEIVER-SIDE FUNCTIONS 
def CBC_encrypt_oracle(byte_string):
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    cipher = AES.new(static_key, AES.MODE_CBC, static_IV)

    # clean the input string
    if b';' in byte_string or b'=' in byte_string:
        byte_string = byte_string.replace(b';', b'";"')
        byte_string = byte_string.replace(b'=', b'"="')
    return cipher.encrypt(PKCS7_pad(prefix + byte_string + suffix, 16))


def check_cipher(ciphertext):
    cipher = AES.new(static_key, AES.MODE_CBC, static_IV)
    decrypted = PKCS7_unpad(cipher.decrypt(ciphertext=ciphertext))
    flag = False
    for b in decrypted:
        if b > 127:
            flag = True
    if flag:
        raise ValueError('Non-ASCII character in url string: ', decrypted)
    return decrypted


# ATTACKER-SIDE FUNCTIONS
def get_work_cipher(CBC_oracle, insertion=None):
    ''' Send insertion to a CBC encryption oracle.'''
    if not insertion:
        insertion = bytes([129, 129, 129, 129]) * 4
    return (CBC_oracle(insertion))


def mix_cipher(ciphertext):
    ''' Chop cipher so that first three blocks B1B2B3 become B1NULLBYTESB1.'''
    if len(ciphertext) < 48:
        raise ValueError('Need cipher of at minimum three blocks.')
    return ciphertext[:16] + bytes(16) + ciphertext[:16] + ciphertext[16:]


def get_exception(remixed_cipher):
    ''' Get exception text from cipher with non ASCII characters.'''
    try:
        check_cipher(remixed_cipher)
    except ValueError as N:
        return N


def clean_exception(exception):
    ''' Strip exception of relevant data; return unencrypted bytes.'''
    return exception.args[1]


def retrieve_key(unencrypted):
    ''' From plaintext of unencrypted remix cipher, retrieve IV used as key.'''
    return bytes_xor(unencrypted[:16], unencrypted[32:48])


# EXECUTING ATTACK IN MAIN LOOP
def main():
    work_cipher = get_work_cipher(CBC_encrypt_oracle)
    remixed = mix_cipher(work_cipher)
    exception = get_exception(remixed)
    unencrypted = clean_exception(exception)
    key = retrieve_key(unencrypted)
    if key == static_key:
        print('Success; static_key is', key)
    else:
        print('Failure. Sads.')


static_key = os.urandom(16)
static_IV = static_key


if __name__ == '__main__':
    main()
