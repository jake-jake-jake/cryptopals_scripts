#!/usr/bin/env python3


import md4
import hashlib
import random

# Server-side functions
def make_hash(data):
    h = md4.MD4()
    h.add(unknown_secret_prefix)
    print(h.count)
    h.add(data)
    print(h.count)
    return h.finish()


def get_random_secret():
    ''' Get a random secret from the dictionary.'''
    return random.choice(open('/usr/share/dict/words', 'r').read().split('\n'))


# unknown_secret_prefix = bytes(get_random_secret(), 'utf-8')
unknown_secret_prefix = b'A'

# Attack side functions
def fake_md4_hash(hex_digest, known_suffix, append_bytes, prefix_len=0):
    ''' Take hex_digest from MD5 with unknown prefix, known_suffix,
        and return possible hash with glue_padding.'''
    padding = generate_padding(len(known_suffix) + prefix_len)
    overide_len = prefix_len + len(known_suffix + padding)
    print(overide_len)
    clone = md4.MD4(hex_digest=hex_digest, est_len=overide_len%64)
    clone.add(append_bytes)
    return clone.finish()


def generate_padding(length):
    ''' Generate MD4 padding for a message of provided length. '''
    # MD4 pads each message so that its length is divisible by 512; this
    # ensures that hash does not carry an unprocessed portion of message
    # along. It also makes inserting glue padding easier, it seems.
    first_56_bytes = b'\x80' + bytes(((56 - (length + 1) % 64) % 64))
    final_128_bits = (length * 8).to_bytes(8, byteorder='little')
    return first_56_bytes + final_128_bits


def find_prefix_length(hash_func, insertion):
    ''' Find byte length of unknown secret prefix.'''
    first_hash = hash_func(insertion)
    check_byte = b'z'
    for _ in range(64):
        # Send insertion plus incremental padding, to find result that matches
        # first_hash. That is the length of unknown prefix. If no matches in 64
        # rounds, it's not a prefix || message hash.
        padding = generate_padding(len(insertion) + _)
        next_hash = fake_md4_hash(first_hash, insertion, check_byte, _)
        target = hash_func(insertion + padding + check_byte)
        if str(next_hash) == target:
            return _
    else:
        raise Exception('Unable to find prefix length; expected %s.' % len(unknown_secret_prefix))


# Is forgery a valid?
def check_hash(cloned_hash, forgery=None):
    ''' Return True if hash is valid for forgery.'''
    if not forgery:
        forgery = unknown_secret_prefix + decoy + padding + insert
    check_hash = md4.MD4()
    check_hash.add(forgery)
    if cloned_hash == check_hash.finish():
        return True
    else:
        return False

decoy = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
insert = b'admin=true;'
# create padding to create intended_forgery, so we can check for success.
padding = generate_padding(len(unknown_secret_prefix + decoy))

def main():
    # decoy and insert variables from Matasano's page.
    decoy = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    insert = b'admin=true;'
    # create padding to create intended_forgery, so we can check for success.
    padding = generate_padding(len(unknown_secret_prefix + decoy))
    intended_forgery = unknown_secret_prefix + decoy + padding + insert
    print('length of first block', len(unknown_secret_prefix + decoy + padding))
    # get digest from decoy; clone the hash; update it with target insertion
    digest = make_hash(decoy)
    # deduced_len = find_prefix_length(make_hash, decoy)
    attack_insertion = decoy + generate_padding(len(decoy) + len(unknown_secret_prefix)) + insert
    fake_hash = fake_md4_hash(digest, decoy, insert, )
    print('attack_insertion: \n', attack_insertion)
    print('fake_hash: \n', fake_hash)
    print('digest:\n', digest)
    if check_hash(fake_hash, intended_forgery):
        print('Extension attack successful with message length %s.' % len(attack_insertion))
        print('Bytes: %s' % attack_insertion)
        print('SHA digest: %s' % fake_hash())

    else:
        print('Attack failed. Exiting.')
        return None

if __name__ == '__main__':
    main()
