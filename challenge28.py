#!/usr/bin/env python3

# Challenge 28


import hashlib
import os
import string
import random

import sha1


def get_random_secret():
    ''' Get a random secret from the dictionary.'''
    return random.choice(open('/usr/share/dict/words', 'r').read().split('\n'))


def get_random_string(length):
    ''' Return random string of specified length.'''
    return ''.join([random.choice(string.printable) for _ in range(length)])


def _test_python_SHA1(key, data):
    return sha1.sha1(key + data)


def _test_hashlib_SHA1(key, data):
    h = hashlib.new('sha1')
    h.update(key + data)
    return h.hexdigest()


def compare_digests(key, rounds=100):
    for _ in range(rounds):
        some_data = bytes(get_random_string(250), 'utf-8')
        pure_python_digest = _test_python_SHA1(key, some_data)
        hashlib_digest = _test_hashlib_SHA1(key, some_data)
        if pure_python_digest != hashlib_digest:
            raise RuntimeError('Hashes not equal', pure_python_digest, hashlib_digest)
    print('Digests identical for %s rounds.' % rounds)


static_key = bytes(get_random_secret(), 'utf-8')
compare_digests(static_key)
