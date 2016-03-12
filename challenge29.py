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
def make_sha1_clone(hex_digest, known_suffix, est_len=None):
    ''' Given hex_digest and estimated length, clone SHAv1 hash.
        Important to note that state is only updated with each round of full
        64 bytes of message.
    '''
    # Instantiate clone
    clone = sha1.Sha1Hash()
    # State is output of digest.
    clone._h = tuple([int(hex_digest[i:i+8], 16)
                  for i in range(0, len(hex_digest), 8)])
    # Set estimated length of message; I figure most secret prefixes are 128
    # bit or less; there is some potential for edgecase problems here. That
    # can be controlled by manually setting len_state +/- 64 bytes.
    if not est_len:
        likely_len_state = (len(known_suffix) + 16) // 64
        likely_len_state = (likely_len_state * 64) + 64
    clone._message_byte_length = likely_len_state
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


def find_prefix_length(hash_func, insertion):
    ''' Find byte length of unknown secret prefix.'''
    first_hash = hash_func(insertion)
    clone = make_sha1_clone(first_hash, insertion)
    check_byte = b'z'
    for _ in range(64):
        # Send insertion plus incremental padding, to find result that matches
        # first_hash. That is the length of unknown prefix. If no matches in 64
        # rounds, it's not a prefix || message hash.
        padding = generate_padding(len(insertion) + _)
        clone.update(check_byte)
        if clone.hexdigest() == hash_func(insertion + padding + check_byte):
            return _
        clone = make_sha1_clone(first_hash, insertion)
    else:
        return None


# Is forgery a valid?
def check_hash(cloned_hash, forgery=None):
    ''' Return True if hash is valid for forgery.'''
    if not forgery:
        forgery = unknown_secret_prefix + decoy + padding + insert
    check_hash = hashlib.new('sha1')
    check_hash.update(forgery)
    if cloned_hash == check_hash.hexdigest():
        return True
    else:
        return False


# Debug scripts
def make_test_hashes():
    test = sha1.Sha1Hash()
    test.update(unknown_secret_prefix)
    test.update(decoy)
    clone = make_sha1_clone(test.hexdigest(), decoy)
    test.update(generate_padding(len(unknown_secret_prefix + decoy)))
    return test, clone


def main():
    # decoy and insert variables from Matasano's page.
    decoy = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    insert = b'admin=true;'
    # create padding to create intended_forgery, so we can check for success.
    padding = generate_padding(len(unknown_secret_prefix + decoy))
    intended_forgery = unknown_secret_prefix + decoy + padding + insert
    # get digest from decoy; clone the hash; update it with target insertion
    digest = make_hash(decoy)
    cloned_sha1 = make_sha1_clone(digest, decoy)
    cloned_sha1.update(insert)
    if check_hash(cloned_sha1.hexdigest(), intended_forgery):
        print('Extension attack successful with message length %s.' % cloned_sha1._message_byte_length)
        return None
    else:
        print('Attack failed with first estimated length. Trying with shorter estimate.')
        cloned_sha1 = make_sha1_clone(digest, decoy)
        cloned_sha1._message_byte_length -= 64
        cloned_sha1.update(insert)

    if check_hash(cloned_sha1.hexdigest(), intended_forgery):
        print('Extension attack successful with message length %s.' % cloned_sha1._message_byte_length)
        return None
    else:
        print('Attack failed with second estimated length. Trying with longer estimate.')
        cloned_sha1 = make_sha1_clone(digest, decoy)
        cloned_sha1._message_byte_length += 64
        cloned_sha1.update(insert)

    if check_hash(cloned_sha1.hexdigest(), intended_forgery):
        print('Extension attack successful with message length %s.' % cloned_sha1._message_byte_length)
        return None
    else:
        print('Attack failed on third attempt. Exiting.')
        return None

if __name__ == '__main__':
    main()
