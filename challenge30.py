#!/usr/bin/env python3
import binascii
import md4
import random
import struct

# Server-side functions
def make_hash(data):
    h = md4.MD4()
    h.add(unknown_secret_prefix)
    h.add(data)
    return h.finish()

def print_internals(has_obj):
    print('Hash data attrib:', has_obj.remainder)
    print('Hash count attrib:', has_obj.count)
    print('Hash h attrib:', has_obj.h)


def get_random_secret():
    ''' Get a random secret from the dictionary.'''
    return random.choice(open('/usr/share/dict/words', 'r').read().split('\n'))


# Attack side functions
def fake_md4_hash(digest, decoy, insert, prefix_len=0):
    ''' Take digest from MD4 with unknown prefix, decoy,
        and return new hash from insertion with glue_padding.'''
    padding = generate_padding(len(decoy) + prefix_len)
    overide_len = prefix_len + len(decoy + padding)
    clone = md4.MD4(data=insert, hex_digest=digest, est_len=overide_len)
    insertion = decoy + padding + insert
    return (insertion, clone.finish())


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
        insert, next_hash = fake_md4_hash(digest=first_hash,
                                             decoy=insertion,
                                             insert=check_byte,
                                             prefix_len=_)
        padding = generate_padding(len(insertion) + _)
        target = hash_func(insertion + padding + check_byte)
        if next_hash == target:
            return _
    else:
        raise Exception('Unable to find prefix length; expected {} for {}.'.format(len(unknown_secret_prefix), unknown_secret_prefix))


# Is forgery a valid?
def check_hash(cloned_hash, forgery=None):
    ''' Return True if hash is valid for forgery.'''
    if not forgery:
        padding = generate_padding(len(unknown_secret_prefix + decoy))
        forgery = unknown_secret_prefix + decoy + padding + insert
    check_hash = md4.MD4()
    check_hash.add(forgery)
    check_digest = check_hash.finish()
    if cloned_hash == check_digest:
        return True
    else:
        return False

# decoy and insert variables from Matasano's page.
decoy = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
insert = b'admin=true;'

unknown_secret_prefix = bytes(get_random_secret(), 'utf-8')

def main():
    start_digest = make_hash(decoy)

    length_unkown_prefix = find_prefix_length(make_hash, decoy)
    # get digest from decoy; clone the hash; update it with target insertion
    # deduced_len = find_prefix_length(make_hash, decoy)
    insertion, fake_hash = fake_md4_hash(digest=start_digest,
                                         decoy=decoy,
                                         insert=insert,
                                         prefix_len=length_unkown_prefix)

    if check_hash(fake_hash):
        print('Extension attack successful with message length %s.' %
              len(insertion))
        print('Bytes: %s' % insertion)
        print('MD4 digest: %s' % fake_hash)

    else:
        print('Attack failed. Exiting.')
        return None

if __name__ == '__main__':
    main()
