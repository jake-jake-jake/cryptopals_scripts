# cryptotools

import itertools, base64, binascii
from collections import Counter

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
            z &= z - 1 # I don't know why this works but it does.
    return count

def hamming_slices(string, keysize):
    slice_a = string[:keysize]
    slice_b = string[keysize:keysize * 2]
    return hamming_distance(slice_a, slice_b)
    
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



# The following four functions are used to clean an input to see if it is English.
# Eventually I will replace with polyglot integration to expand language functionality.
def is_language(string, dictionary, word_percentage = 20, letter_percentage = 85):
    ''' Checks if string is a language by comparing words in string with
        loaded dictionary. Returns true if given percentage of word matches 
        and letters in string is high enough. Default values: word_percentage
        is 20 and letter_percentage is 85.
    '''
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



        
