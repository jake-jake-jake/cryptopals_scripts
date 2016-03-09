import hashlib
import os
import string
import random

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
def find_len_secret_key(hash_function):
    ''' '''
    pass
    

