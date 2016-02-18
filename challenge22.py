#!/usr/bin/env python3

# Cryptopals Challenge #22, get seed from output of Mersenne Twister RNG
# Detempering algos derived from Crypto 101 book
from random import randint
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

    def _get_intermediate_variable(self, num):
        ''' Return intermediate shift variable for untempering MT output.'''
        untemp = num
        for _ in range(5):
            untemp = untemp << 7
            untemp = num ^ (untemp & 2636928640)
        return untemp

    def _recover_state(self, num):
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
        output = self._recover_state(output)
        return output


def make_psuedo_random_nums():
    seed_time = int(time()) - randint(40, 1000)
    random_twister = Mersenne(seed_time)
    return seed_time, random_twister.temper()


def crack_Mersenne_seed(num):
    now = int(time())
    for i in range(10000):
        test_my = Mersenne(now - i)
        if test_my.temper() == num:
            return now - i
    else:
        return None

for num in range(1):
    random_seed, number = make_psuedo_random_nums()
    guess_seed = crack_Mersenne_seed(number)
    if guess_seed == random_seed:
        print('Success `cracking` random seed:', random_seed)
        print('guess_seed:', guess_seed)
