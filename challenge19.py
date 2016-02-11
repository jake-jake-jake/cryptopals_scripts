#!/usr/bin/env python3

import binascii
import struct
import os

from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptotools import check_chars as score_freqs

PLAINTEXTS = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
              'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
              'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
              'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
              'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
              'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
              'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
              'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
              'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
              'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
              'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
              'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
              'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
              'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
              'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
              'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
              'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
              'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
              'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
              'U2hlIHJvZGUgdG8gaGFycmllcnM/',
              'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
              'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
              'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
              'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
              'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
              'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
              'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
              'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
              'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
              'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
              'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
              'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
              'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
              'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
              'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
              'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
              ]


def decrypt_AES_CTR(key, nonce, ciphertext):
    ctr = Counter.new(64, prefix=nonce, little_endian=True, initial_value=0)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


def encrypt_AES_CTR(key, nonce, plaintext):
    ctr = Counter.new(64, initial_value=0, little_endian=True, prefix=nonce)
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)


def make_ciphers(encrypt_func, key, nonce_or_IV, base64_plaintexts):
    ''' Return list of ciphers using encrypt_func base64 encoded plaintexts.'''
    return [encrypt_func(key, nonce_or_IV, binascii.a2b_base64(plaintext))
            for plaintext in base64_plaintexts]


def concatenate_nonce_slices(list_ciphers):
    ''' Create a list of indexed cipher-litters for frequency analysis.'''
    slices = [cipher[i::16] for i in range(8) for cipher in list_ciphers]
    return [b''.join(slices[i::8]) for i in range(8)]

def single_byte_xor(byte_literal, i):
    ''' Xor byte_literal against i.'''
    return b''.join(bytes([a ^ b]) for a,b 
                    in zip(byte_literal, bytes([i]) * len(byte_literal)))

def score_bytes_by_nonce_index(nonce_indices):
    ''' Return 5 highest scores for frequency for each nonce byte.'''
    scores = []
    for index in nonce_indices:
        byte_scores = [(bytes([i]), score_freqs(single_byte_xor(index, i))) for i in range(256)]
        byte_scores.sort(key=lambda x: x[1], reverse=True)
        scores.append(byte_scores[:5])
    return scores


static_key = os.urandom(16)
nonce = struct.pack('<Q', 0)

list_of_ciphers = make_ciphers(encrypt_AES_CTR, static_key, nonce, PLAINTEXTS)
nonce_slices = concatenate_nonce_slices(list_of_ciphers)
possible_key_stream = score_bytes_by_nonce_index(nonce_slices)