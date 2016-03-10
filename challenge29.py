import hashlib
import os
import random
import string

import sha1


# Server-side functions
def make_hash(data):
    h = hashlib.new('sha1')
    h.update(unknown_secret_prefix)
    h.update(data)
    return h.hexdigest()


def get_random_secret():
    ''' Get a random secret from the dictionary.'''
    return random.choice(open('/usr/share/dict/words', 'r').read().split('\n'))


unknown_secret_prefix = bytes(get_random_secret(), 'utf-8')


# Attacker-side functions
def make_sha1_clone(hex_digest, message, est_len):
    ''' Given hex_digest, message, and estimated length, clone SHAv1 hash.'''
    clone = sha1.Sha1Hash()
    state = tuple([int(hex_digest[i:i+8], 16)
                  for i in range(0, len(hex_digest), 8)])
    remainder_index = (len(message) // 64) * 64
    unprocessed = message[remainder_index[remainder_index:]]
    clone.clone_state(digest, unprocessed, length)
    return clone


def generate_padding(length):
    ''' Generate SHAv1 padding for a message of provided length. '''
    # Total length of padding for SHAv1 is 512 bits. These are produced by
    # appending a 1 bit, then enough zero bits so that 
    #           len_msg + 1 + len_zero_bits == 448 (mod 512) 
    # This leaves space for a long long that represents bitwise length of 
    # message to be appended at end. So, 
    #           msg + 1 + zero_bits + long_long_of_msg_chars == 512 (mod 512)
    first_64_bytes = b'\x80' + bytes(((56 - (length + 1) % 64) % 64))
    final_128_bits = (length * 8).to_bytes(8, byteorder='big')
    return first_64_bytes + final_128_bits


def get_digest_and_check_variable(hashfunc, message):
    ''' Send message to hashfunc twice to get digest and expected update output.'''
    digest = hashfunc(message)
    expected_update = hashfunc(message + message)
    return digest, expected_update

message = b'comment1=cooking%20MCs;userdata=foo;'
output, target = get_digest_and_check_variable(make_hash, message)

