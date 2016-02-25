# challenge6.py

import cryptotools as ct
import itertools

def find_potential_keys(cipher, key_len):
    ''' Return potential keys for a given key length by judging letter frequency'''
    key_potentials = []
    cipher_slices = ct.slice_string_by_block(cipher, key_len)
    for slc in cipher_slices:
        slice_key_candidates = []
        for _ in range(256):
            cm = zip(list(slc), itertools.cycle([_]))
            xor_attempt = bytes([a ^ b for a, b in cm])
            slice_key_candidates.append((chr(_), ct.check_chars(xor_attempt)))
        slice_key_candidates.sort(key=lambda x: x[1], reverse=True)
        key_potentials.append(slice_key_candidates[:1])
    return[x[0] for x in key_potentials]

def try_key_lets(cipher, key_potentials):
    print('Trying keys... \n')
    dictionary = ct.load_dictionary()
    for attempt in itertools.product(*key_potentials):
        cm = zip(list(encrypted), itertools.cycle(attempt))
        cm = [chr(x ^ ord(y)) for x, y in cm]
        if ct.is_language(''.join(cm), dictionary):
            print('Decrypted text:\n{}\nKey:\n{}'.format(attempt, cm))
        else:
            continue

def hamming_by_key_len(cipher, max_len=40, blocks=6):    
    ''' Return dictionary of hamming distance by key length.'''
    keys_ham_distance = {}
    for key_len in range(2, max_len + 1):
        keys_ham_distance[key_len] = 0
        for block in range(blocks):
            keys_ham_distance[key_len] +=  ct.hamming_slices(encrypted, key_len, block) / key_len
        keys_ham_distance[key_len] /= blocks
    return keys_ham_distance



if __name__ == '__main__':
    with open('6.txt') as f:
        encrypted = f.read()
    encrypted = ct.base64_to_bytes(encrypted)
    attempts = hamming_by_key_len(encrypted)
    lowest_hamming = sorted(attempts, key=attempts.get)[:5]
    print('Prospective keys:\n{}'.format(lowest_hamming))

    dictionary = ct.load_dictionary()

    for key_len in lowest_hamming:
        pot_keys = find_potential_keys(encrypted, key_len)
        pot_lets = [x for x, y in pot_keys]
        attempt = ''.join([chr(x) for x in ct.cycle_xor(encrypted, pot_lets)])
        if ct.is_language(attempt, dictionary):
            print('Potential key:\n{}\nDecryption:\n{}'.format(''.join(pot_lets), attempt))
        else:
            print('Key length of {} does not produce match on most likely letters.'.format(key_len))
