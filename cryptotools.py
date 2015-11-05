# cryptotools

import base64, binascii
import collections 
import itertools 
import random
import string


COMMON_ENGLISH_LETTERS = 'ETAOIN SHRDLU'

def hex_to_bytes(hex_string):
    ''' Return bytes object from hexadecimal string. 
        This is a wrapper function. '''
    return bytes.fromhex(hex_string)

def bytes_xor(a, b):
    ''' Xor two bit strings of equal length.'''
    if len(a) != len(b):
        raise ValueError('Xored bytestrings must be of equal length.')
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_base64(b):
    return base64.encodebytes(b).decode()

def base64_to_bytes(b64):
    return base64.b64decode(b64).decode()

def bytes_to_hex(b):
    return binascii.hexlify(b)

# Following functions used for calculating Hamming distance in bits.
# I borrowed the the core operand (z &= z -1) from the internet, which
# borrowed it from a 1960s compsci paper.
def hamming_distance(a, b):
    '''Return bitwise Hamming distance between equal length strings'''
    if len(a) != len(b):
        raise ValueError('Undefined for strings of unequal length')
    count = 0
    bits_a = [int(bin(ord(char)), 2) for char in a]
    bits_b = [int(bin(ord(char)), 2) for char in b]
    for ch1, ch2 in zip(bits_a, bits_b):
        z = ch1 ^ ch2
        while z:
            count += 1
            z &= z - 1 # This is pretty brilliant.
    return count

def hamming_slices(string, keysize, start_block = 0):
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
def is_language(string, dictionary, word_percentage = 20, letter_percentage = 85):
    ''' Checks if string is a language by comparing words in string with
        loaded dictionary. Returns true if given percentage of word matches 
        and letters in string is high enough. Default values: word_percentage
        is 20 and letter_percentage is 85. '''
    word_match = (get_dictionary_percentage(string, dictionary) * 100) >= word_percentage
    sufficient_letters = (len(strip_string(string))/len(string) * 100) >= letter_percentage
    return word_match and sufficient_letters

def strip_string(string):
    ''' Removes nonalphabetic characters from string, preserving spaces. '''
    stripped_string = [char for char in string if char.isalpha() or char in ' \t\n']
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
# key byte produces usable plaintext bytes.
def check_chars(candidate_string, minimum_percentage = .60):
    counts = collections.Counter(candidate_string)
    hits = 0
    for let, count in counts.most_common(13):
        if let.upper() in COMMON_ENGLISH_LETTERS:
            hits += 1
        else:
            continue
    return hits/len(COMMON_ENGLISH_LETTERS) > minimum_percentage
