#!/usr/bin/env python3

# Cryptopals Challenge #22, get seed from output of Mersenne Twister RNG
# Detempering algos derived from Crypto 101 book
from time import time


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
            y = _int32((self.state[i] & 0x80000000) +
                       (self.state[(i + 1) % 624] & 0x7fffffff))
            self.state[i] = self.state[(i + 397) % 624] ^ y >> 1
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

    def _untemper_first_shift(self, num):
        ''' Return first intermediate variable for untempering MT output.'''
        untemp = num
        for _ in range(5):
            untemp = untemp << 7
            untemp = num ^ (untemp & 2636928640)
        return untemp

    def _untemper_second_shift(self, num):
        ''' Return untempered MT state value from intermediate shift variable. '''
        state = num
        for _ in range(2):
            state = state >> 11
            state = state ^ num
        return state

    def untemper(self, output):
        ''' Return untempered state value from output.'''
        output = output ^ output >> 18
        output = output ^ ((output << 15) & 4022730752)
        output = self._untemper_first_shift(output)
        output = self._untemper_second_shift(output)
        return output

this_time = int(time())
my_twister = Mersenne(this_time)
state_at_start = my_twister.state[0]
number = my_twister.temper()
untempered_number = my_twister.untemper(number)

print('this_time:', this_time)
print('first index value of my_twister:', state_at_start)
print('number:', number)
print('number run through untempering function:', untempered_number)