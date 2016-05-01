#!/usr/bin/env python
import binascii
import struct


def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))


def F(x,y,z):
    return (x & y) | (~x & z)


def G(x,y,z):
    return (x & y) | (x & z) | (y & z)


def H(x,y,z):
    return x ^ y ^ z


class MD4(object):
    def __init__(self, data=b'', hex_digest=None, est_len=0):
        self.remainder = data
        if not est_len:
            self.count = 0
        else:
            self.count = est_len // 64
        if not hex_digest:
            self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
            ]
        else:
            self.h = [int(hex_digest[i:i + 8], 16)
                      for i in range(0, len(hex_digest), 8)]
            print([hex(x) for x in self.h])

    def _add_chunk(self, chunk):
        self.count += 1
        X = list(struct.unpack('<16I', chunk) + (None,) * (80 - 16))
        h = [x for x in self.h]

        # Round 1
        s = (3, 7, 11, 19)
        for r in range(16):
            i = (16 - r) % 4
            k = r
            h[i] = leftrotate((h[i] + F(h[(i + 1) % 4],
                                        h[(i + 2) % 4], h[(i + 3) % 4]) +
                               X[k]) % 2**32, s[r % 4])

        # Round 2
        s = (3, 5, 9, 13)
        for r in range(16):
            i = (16 - r) % 4
            k = 4 * (r % 4) + r // 4
            h[i] = leftrotate((h[i] + G(h[(i + 1) % 4], h[(i + 2) % 4],
                                        h[(i + 3) % 4]) +
                               X[k] + 0x5a827999) % 2**32, s[r % 4])

        # Round 3
        s = (3, 9, 11, 15)
        k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for r in range(16):
            i = (16 - r) % 4
            h[i] = leftrotate((h[i] + H(h[(i + 1) % 4], h[(i + 2) % 4],
                                        h[(i + 3) % 4]) +
                               X[k[r]] + 0x6ed9eba1) % 2**32, s[r % 4])

        for i, v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b''
        for chunk in range(0, len(message) - r, 64):
            self._add_chunk(message[chunk:chunk + 64])
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.add(b'\x80' +
                 b'\x00' * ((55 - l) % 64) +
                 struct.pack('<Q', l * 8))
        out = struct.pack('<4I', *self.h)
        self.__init__()
        return binascii.hexlify(out)

if __name__=='__main__':
    test = ((b'', b'31d6cfe0d16ae931b73c59d7e0c089c0'),
            (b'a', b'bde52cb31de33e46245e05fbdbd6fb24'),
            (b'abc', b'a448017aaf21d8525fc10ae87aa6729d'),
            (b'message digest', b'd9130a8164549fe818874806e1c7014b'),
            (b'abcdefghijklmnopqrstuvwxyz',
                b'd79e1c308aa5bbcdeea8ed63df412da9'),
            (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                b'043f8582f241db351ce627e153e7f0e4'),
            (b'12345678901234567890123456789012345678901234567890123456789012345678901234567890',
                b'e33b4ddc9c38f2199c3e7b164fcc0536'))
    md = MD4()
    for t, h in test:
        md.add(t)
        d = md.finish()
        if d == h:
            print('pass')
        else:
            print('FAIL: {0}: {1}\n\texpected: {2}'.format(t, d, h))
