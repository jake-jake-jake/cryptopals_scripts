#!/usr/bin/env python3

# Cryptopals Challenge #23, generate state from detempered MT outputs.
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

    def clone_state(self, list_of_outputs):
        ''' Clone a Mersenne Twister from full cycle of outputs.'''
        if not len(list_of_outputs) == 624:
            raise ValueError('Provide 624 output values, not {}.').format(
                             len(list_of_outputs))
        new_state = [self.untemper(output) for output in list_of_outputs]
        self.index = 624
        self.state = new_state




RNG_original = Mersenne(int(time()))
RNG_clone = Mersenne(0)

outputs = [RNG_original.temper() for _ in range(624)]
RNG_clone.clone_state(outputs)

for i in range(624):
    if not RNG_original.temper() == RNG_clone.temper():
        print('Failure')
else:
    print('If no failures, success.')