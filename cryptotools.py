# cryptotools

import binascii
import itertools
import random


COMMON_ENGLISH_LETTERS = 'ETAOIN SHRDLU'


def hex_to_bytes(hex_string):
    ''' Return bytes object from hexadecimal string.'''
    return bytes.fromhex(hex_string)


def bytes_xor(a, b):
    ''' Xor two bytestrings of equal length.'''
    if len(a) != len(b):
        raise ValueError('Xored bytestrings must be of equal length.')
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])


def bytes_to_base64(b):
    return binascii.b2a_base64(b)


def base64_to_bytes(b64):
    return binascii.a2b_base64(b64)


def bytes_to_hex(b):
    return bytes.hex(b)


def cycle_xor(pt, key):
    ''' Xors a plaintext or ciphertext against a key, cycling on end of key.'''
    cm = zip(list(pt), itertools.cycle(list(key)))
    cm = [x ^ ord(y) for x, y in cm]
    return cm

# Following functions used for calculating Hamming distance in bits.
# I borrowed the the core operation (z &= z -1) from the internet, which
# borrowed it from a 1960s compsci paper.


def hamming_distance(a, b):
    '''Return bitwise Hamming distance between equal length strings'''
    if len(a) != len(b):
        raise ValueError('Undefined for strings of unequal length')
    count = 0
    bits_a = [int(bin(char), 2) for char in a]
    bits_b = [int(bin(char), 2) for char in b]
    for ch1, ch2 in zip(bits_a, bits_b):
        z = ch1 ^ ch2
        while z:
            count += 1
            z &= z - 1  # This is pretty brilliant.
    return count


def hamming_slices(string, keysize, start_block=0):
    ''' Return bitwise hamming distance of the two blocks of keysize length.
        Defaults to index 0; can be keyed to subsequent blocks.'''
    index = keysize * start_block
    slice_a = string[index: index + keysize]
    slice_b = string[index + keysize: index + keysize * 2]
    return hamming_distance(slice_a, slice_b)


def random_hamming(string, keysize):
    ''' Return bitwise hamming distance of two random blocks of keysize length.'''
    index = random.randint(0, len(string) - (2 * keysize))
    slice_a = string[index:index + keysize]
    slice_b = string[index + keysize:index + (2 * keysize)]
    return hamming_distance(slice_a, slice_b)


def slice_string_by_block(string, keysize):
    ''' Create a list of subsequences from string, so that each subsequence is composed
        of the Nth letter of each keysize block of string.'''
    subs = []
    for _ in range(keysize):
        subs.append(string[_::keysize])
    return subs

# Loads a dictionary to check cipher hacks against. In the main() function, defaults to
# loading the dictionary.txt provided with Hacking Ciphers with Python
def load_dictionary(file_name = None):
    ''' Loads a dictionary file. Defaults to 'dictionary.txt' provided by Al 
        Sweigart in his python hacking book.  '''
    dict_name = file_name or 'dictionary.txt'
    dict_words = {}
    with open(dict_name) as fo:      # Loads dictionary file
        for word in fo.read().split('\n'):
            dict_words[word] = None
    return dict_words



# The following three functions are used to clean an input to see if it is English.
# Eventually I will replace with polyglot integration to expand language functionality.
def is_language(data, dictionary, word_percentage = 20, letter_percentage = 85):
    ''' Checks if string is a language by comparing words in string with
        loaded dictionary. Returns true if given percentage of word matches
        and letters in string is high enough. Default values: word_percentage
        is 20 and letter_percentage is 85. '''
    try:
        string = str(data)
    except TypeError:
        return False
    word_match = (get_dictionary_percentage(string, dictionary) * 100) >= word_percentage
    sufficient_letters = (len(strip_string(string))/len(string) * 100) >= letter_percentage
    return word_match and sufficient_letters


def strip_string(string):
    ''' Removes nonalphabetic characters from string, preserving spaces. '''
    stripped_string = [char for char in string
                       if char.isalpha() or char in ' \t\n']
    return ''.join(stripped_string)


def get_dictionary_percentage(string, dictionary):
    ''' Returns a float conveying percentage of dictionary words in 
        string, from 0.0 to 1.0. '''
    word_list = strip_string(string).split()
    if word_list == []:
        return 0.0

    dictionary_words = 0
    for word in word_list:
        if word.upper() in dictionary:
            dictionary_words += 1
    return float(dictionary_words/len(word_list))


# The functions are used to test the likelihood of slices of a ciphertext to see if the xored
# key byte produces plaintext with a likely-to-be-English distribution of chars.
def check_chars(candidate_string):
    ''' Return a score of an xor attempt using letter frequencies as points'''
    score = 0
    # From http://www.data-compression.com/english.html
    freqs = {
        'a': 0.0651738,
        'b': 0.0124248,
        'c': 0.0217339,
        'd': 0.0349835,
        'e': 0.1041442,
        'f': 0.0197881,
        'g': 0.0158610,
        'h': 0.0492888,
        'i': 0.0558094,
        'j': 0.0009033,
        'k': 0.0050529,
        'l': 0.0331490,
        'm': 0.0202124,
        'n': 0.0564513,
        'o': 0.0596302,
        'p': 0.0137645,
        'q': 0.0008606,
        'r': 0.0497563,
        's': 0.0515760,
        't': 0.0729357,
        'u': 0.0225134,
        'v': 0.0082903,
        'w': 0.0171272,
        'x': 0.0013692,
        'y': 0.0145984,
        'z': 0.0007836,
        ' ': 0.1918182
        }
    for char in candidate_string:
        try:
            lowercase = chr(char)
        except AttributeError:
            continue
        if lowercase.lower() in freqs:
            score += freqs[lowercase.lower()]
    return score


def PKCS7_pad(data, block_length):
    ''' Pad data with PKCS7 padding.'''
    padding = block_length - (len(data) % block_length)
    return (data + bytes([padding])*padding)


def PKCS7_unpad(data):
    ''' Remove PKCS7 padding.'''
    if data[-1] == 0 or not len(set(data[-data[-1]:])) == 1:
        raise ValueError('Invalid padding.')
    return data[:len(data)-data[-1]]