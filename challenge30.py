#!/usr/bin/env python3


import md4
import hashlib
import random

# Server-side functions
def make_hash(data):
    h = md4.MD4()
    h.add(unknown_secret_prefix)
    h.add(data)
    print(h.h)
    return h.finish()


def test_hash():
    h = md4.MD4()
    h.add(unknown_secret_prefix)
    h.add(decoy)
    h.add(padding)
    h.add(insert)
    return h.finish()

def get_random_secret():
    ''' Get a random secret from the dictionary.'''
    return random.choice(open('/usr/share/dict/words', 'r').read().split('\n'))


# unknown_secret_prefix = bytes(get_random_secret(), 'utf-8')
unknown_secret_prefix = b'A'


# Attack side functions
def fake_md4_hash(digest, known_suffix, append_bytes, prefix_len=0):
    ''' Take digest from MD4 with unknown prefix, known_suffix,
        and return new hash from insertion with glue_padding.'''
    padding = generate_padding(len(known_suffix) + prefix_len)
    overide_len = prefix_len + len(known_suffix + padding)
    clone = md4.MD4(data=append_bytes, hex_digest=digest, est_len=overide_len)
    print('clone count', clone.count)
    print('clone state', clone.h)
    print('clone remainder', clone.remainder)
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
        raise Exception('Unable to find prefix length; expected %s.' %
                        len(unknown_secret_prefix))


# Is forgery a valid?
def check_hash(cloned_hash, forgery=None):
    ''' Return True if hash is valid for forgery.'''
    if not forgery:
        forgery = unknown_secret_prefix + decoy + padding + insert
    check_hash = md4.MD4()
    check_hash.add(forgery)
    check_hash = check_hash.finish()
    print(cloned_hash, check_hash)
    if cloned_hash == check_hash:
        return True
    else:
        return False


# decoy and insert variables from Matasano's page.
decoy = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
insert = b'admin=true;'
# create padding to create intended_forgery, so we can check for success.
padding = generate_padding(len(unknown_secret_prefix + decoy))
intended_forgery = decoy + padding + insert
failsafe = test_hash()
target_digest = make_hash(intended_forgery)


def main():
    start_digest = make_hash(decoy + padding)
    print('HASH OF INTENDED FORGERY:', target_digest)
    print('HASH OF DECOY:', start_digest)
    # get digest from decoy; clone the hash; update it with target insertion
    # deduced_len = find_prefix_length(make_hash, decoy)
    attack_insertion = decoy + generate_padding(len(decoy) +
                       len(unknown_secret_prefix))
    fake_hash = fake_md4_hash(digest=start_digest, known_suffix=decoy,
                              append_bytes=insert, prefix_len=1)
    print('fake_hash: \n', fake_hash)
    print('digest:\n', target_digest)
    print('test_hash:', test_hash())
    if check_hash(fake_hash):
        print('Extension attack successful with message length %s.' %
              len(attack_insertion))
        print('Bytes: %s' % attack_insertion)
        print('MD4 digest: %s' % fake_hash())

    else:
        print('Attack failed. Exiting.')
        return None

if __name__ == '__main__':
    main()
