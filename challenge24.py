#!/usr/bin/env python3

# Cryptopals Challenge #24. Create a MT stream cipher, then discover seed.
# Throughout, using big endian byte order for ints.

from time import time
import os


def _int32(x):
    ''' Return the 32 least significant bits of an int.'''
    return int(0xFFFFFFFF & x)


class Mersenne:
    def __init__(self, seed=0):
        self.state = [0] * 624
        self.index = 624
        self.state[0] = seed
        for i in range(1, 624):
            self.state[i] = _int32(
                1812433253 * (self.state[i - 1] ^ self.state[i - 1] >> 30) + i)

    def regenerate(self):
        ''' Regenerate state after nums have been called.'''
        for i in range(624):
            # take most significant bit of state[i] and 31 least sig of
            # state[i+1]
            y = _int32((self.state[i] & 0x80000000) +
                       (self.state[(i + 1) % 624] & 0x7fffffff))
            # set state[i] equal to that sum shifted 1 bit right and xored
            # vs state[i+397 mod. len(state)]
            self.state[i] = self.state[(i + 397) % 624] ^ y >> 1
            # if y is even, apply another bit mask
            if y % 2:
                self.state[i] = self.state[i] ^ 0x9908b0df
        self.index = 0

    def temper(self):
        ''' Return psuedorandom number drawn from state.'''
        # Regenerate state at index of 624.
        if self.index >= 624:
            self.regenerate()
        y = self.state[self.index]
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        self.index += 1
        return _int32(y)

    def _get_intermediate_variable(self, num):
        ''' Return intermediate shift variable for untempering MT output.'''
        untemp = num
        for _ in range(5):
            untemp = untemp << 7
            untemp = num ^ (untemp & 2636928640)
        return untemp

    def _recover_state_elem(self, num):
        ''' Return untempered MT state from intermediate shift variable. '''
        state = num
        for _ in range(2):
            state = state >> 11
            state = state ^ num
        return state

    def untemper(self, output):
        ''' Return untempered state value from output.'''
        output = output ^ output >> 18
        output = output ^ ((output << 15) & 4022730752)
        output = self._get_intermediate_variable(output)
        output = self._recover_state_elem(output)
        return output

    def clone_state(self, list_of_outputs):
        ''' Clone a Mersenne Twister from full cycle of outputs.'''
        if not len(list_of_outputs) == 624:
            raise ValueError('Provide 624 output values, not {}.').format(
                             len(list_of_outputs))
        new_state = [self.untemper(output) for output in list_of_outputs]
        self.index = 624
        self.state = new_state

    def recover_seed(self, state):
        ''' Take regenerated state and return 0 index of previous state.'''
        pass


def MT_stream_cipher(data, MT, key):
    ''' Encrypt or decrypt bytes  by xor vs keystream made from MT output.'''
    try:
        seed = int.from_bytes(key, 'big')
    except ValueError:
        raise ('Unable to convert key to seed.')
    key_generator = MT(seed)
    key_stream = []
    while len(key_stream) < len(data):
        output_bytes = list(key_generator.temper().to_bytes(4, 'big'))
        for byte in output_bytes:
            key_stream.append(byte)
    print('DEBUG: key_stream and length of key_stream,', key_stream, len(key_stream))
    print('DEBUG: length of data,', len(data))
    return b''.join(bytes([a ^ b]) for a,b in zip(data, key_stream))




this_key = os.urandom(2)
some_data = 'YELLOW SUBMARINE' * 5
bytes_data = bytes(some_data, 'utf-8')

cipher = MT_stream_cipher(bytes_data, Mersenne, this_key)
decipher = MT_stream_cipher(cipher, Mersenne, this_key)
print('DEBUG: cipher, \n', cipher)
print('DEBUG: decipher, \n', decipher)