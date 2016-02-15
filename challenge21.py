#!/usr/bin/env python3

# Implement the Mersenne Twister
# You apparently don't have to specify the type of int here.
# This class draws heavily from the Crypto 101 book.

class Mersenne:
    ''' Return psuedorandom numbers from the Mersenne twister.'''
    _TEMPER_MASK_1 = 0x9d2c5680
    _TEMPER_MASK_2 = 0xefc60000
    def __init__(self, seed=0):
        self.state = []
        self.index = 0
        self.seed = seed
        self.initialize()

    def _int32(self, x):
        ''' Return the 32 least significant bits.'''
        return int(0xFFFFFFFF & x)

    def initialize(self, seed=None):
        ''' Generate initial state from seed.'''
        self.index = 0
        seed = seed or self.seed
        state = [seed]
        for i in range(1, 624):
            prev = state[-1]
            num = 0x6c078965 * (prev ^ (prev >> 30)) + 1
            state.append(self._int32(num))
        self.state = state

    def regenerate(self):
        ''' Regenerate state after nums have been called.'''
        for i in range(624):
            y = self._int32(self.state[i] & 0x80000000)
            y += self.state[(i+ 1) % 624] & 0x7fffffff
            z = self._int32(self.state[(i + 397) % 624])
            self.state[i] = self._int32(z ^ (y >> 1))
            if y % 2:
                self.state[i] ^= 0x9908b0df

    def temper(self):
        ''' Return psuedorandom number drawn from state.'''
        # Regenerate state at index of 0.
        if self.index == 0:
            self.regenerate()
        y = self.state[self.index]
        y ^= y >> 11
        y ^= (y << 7) & self._TEMPER_MASK_1
        y ^= (y << 15) & self._TEMPER_MASK_2
        y ^= (y >> 18)
        self.index = (self.index + 1) % 624 
        return self._int32(y)

class operaRandom:
    """A Mersenne twister random generator"""
    length=624
    bitMask_32=(2**32)-1
    bitPow_31=2**31
    def __init__(self,seed):
        self.idx=0
        self.mt= [z for z in range(self.length)]
        self.mt[0]=seed
        for i in range(1,self.length):
            self.mt[i]=(1812433253*(self.mt[i-1]^(self.mt[i-1]>>30))+i)&self.bitMask_32

    def get(self):
        if self.idx==0:
            self.gen()
        y =self.mt[self.idx]
        y^= y>>11
        y^=(y<< 7)&2636928640
        y^=(y<<15)&4022730752
        y^= y>>18

        self.idx=(self.idx+1)%self.length
        return y

    def gen(self):
        for i in range(self.length):
            y=(self.mt[i]&self.bitPow_31)+(self.mt[(i+1)%self.length]&(self.bitPow_31-1))
            self.mt[i]=self.mt[(i+397)%self.length]^(y>>1)
            if y%2:
                self.mt[i]^=2567483615
seed = 100
fail = False
my_mersenne = Mersenne(seed=seed)
their_mersenne = operaRandom(seed=seed)

for i in range(100):
    if my_mersenne.temper() == their_mersenne.get():
        print('Success.')
        continue
    else:
        fail = True

if fail:
    print('Failure.')
else:
    print('Mersenne Twister appears to be working.')
