# -*- coding: utf-8 -*-
"""
Implementing the SHA512 hash function was tough (man, do I suck at cryptography), I tried multiple resources like
https://locklessinc.com/articles/crypto_hash/ which turned out to be too much info for a newbie like me, a couple
answers on Stack Exchange like https://security.stackexchange.com/questions/33860/how-does-hashing-work which were
pretty much the same stuff but in a simpler language. I also found the GitHub repository for PySHA2 algorithm
(https://github.com/thomdixon/pysha2/blob/master/sha2/sha512.py) which, surprise surprise, went totally over my head.
Eventually, I ended up at the Wikipedia page for SHA2 (https://en.wikipedia.org/wiki/SHA-2) where I saw the pseudocode
for SHA512 and realized that it was the same stuff as the PySHA2 code. In the end, I pretty much copied the SHA512
algorithm from PySHA2 (since I found there is no standard 'alternative' way to write that same code, which might
actually be a good thing for reasons I don't understand :P
"""

import copy
import struct


def _sha_backend(text_to_hash: str, _buffer: str, _counter: int,
                 _output_size: int, hex_output: bool = False):
    """
    backend function that hashes given string
    :param text_to_hash: message to be hashed (str)
    :param _buffer: buffer string for hashing (str)
    :param _counter: counter number for hashing (int)
    :param _output_size: size of a single chunk (int)
    :param hex_output: whether hexdigest() needs to be returned (bool)
    :return: hash value if hex_output is True (int) or hash hex if hex_output is False (hex)
    """
    def _rit_rot(on: int, by: int) -> int:
        """
        helper function for right rotation as it isn't done by a simple bitwise operation (xor is '^')
        :param on: value to be rotated
        :param by: value by which to rotate
        :return: right rotated 'on'
        """
        return ((on >> by) | (on << (64 - by))) & 0xFFFFFFFFFFFFFFFF

    # initialize variables
    variable_x = _counter & 0x7F
    length = str(struct.pack('!Q', _counter << 3))

    # make the initial hashes and round constants
    _initial_hashes = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                       0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    _round_constants = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

    # set the thresholds
    if variable_x < 112:
        padding_len = 111 - variable_x
    else:
        padding_len = 239 - variable_x

    # make a copy of the text_to_hash before starting hashing
    text_copy = copy.deepcopy(text_to_hash)
    pad = '\x80' + ('\x00' * (padding_len + 8)) + length
    text_copy += pad[1:]

    # create variables for cycling
    _buffer += text_copy
    _counter += len(text_copy)

    # assert the variables are correct
    if not text_copy:
        return
    if type(text_copy) is not str:
        raise TypeError("Invalid Object! Please enter a valid string for hashing!")

    # break the buffer into 128-bit chunks
    while len(_buffer) >= 128:
        chunk = _buffer[:128].encode()

        # start the hashing process
        # to begin, create a place to store the 80 words that we'll make
        words = [0]*80

        # first 16 words will be saved without any changes
        words[:16] = struct.unpack('!16Q', chunk)

        # extend these 16 words into the remaining 64 words of 'message schedule array'
        for i in range(16, 80):
            part_1 = _rit_rot(words[i-15], 1) ^ _rit_rot(words[i-15], 8) ^ (words[i-15] >> 7)
            part_2 = _rit_rot(words[i-2], 19) ^ _rit_rot(words[i-2], 61) ^ (words[i-2] >> 6)
            words[i] = (words[i-16] + part_1 + words[i-7] + part_2) & 0xFFFFFFFFFFFFFFFF

            # create the working variables
            a, b, c, d, e, f, g, h = _initial_hashes

            # start the compression function
            for z in range(80):
                var_1 = _rit_rot(a, 28) ^ _rit_rot(a, 34) ^ _rit_rot(a, 39)
                var_2 = _rit_rot(e, 14) ^ _rit_rot(e, 18) ^ _rit_rot(e, 41)
                var_3 = (a & b) ^ (a & c) ^ (b & c)
                var_4 = (e & f) ^ ((~e) & g)
                temp_1 = var_1 + var_3
                temp_2 = h + var_2 + var_4 + _round_constants[z] + words[z]

                # remix the hashes
                h = g
                g = f
                f = e
                e = (d + temp_2) & 0xFFFFFFFFFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp_1 + temp_2) & 0xFFFFFFFFFFFFFFFF

                # add this chunk to initial hashes
                _initial_hashes = [(x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip(_initial_hashes,
                                                                                [a, b, c, d, e, f, g, h])]

        # update buffer
        _buffer = _buffer[128:]

    # return the hash value
    return_val = [hex(stuff) for stuff in _initial_hashes[:_output_size]]

    if hex_output is True:
        return_val = [int(stuff, base=16) for stuff in return_val]
        return return_val

    return ''.join(return_val)


def sha_512(text_to_hash: str, hex_digest: bool = False) -> str:
    """
    frontend function for SHA512 hashing
    :return: hashed string
    """
    # before anything, check if the input is correct
    if not text_to_hash:
        return ""
    if type(text_to_hash) is not str:
        raise TypeError("Invalid content! Please provide content in correct format for hashing!")

    # initialize default variables
    _buffer = ''
    _counter = 0
    _output_size = 8

    # start the backend function
    return _sha_backend(text_to_hash, _buffer, _counter, _output_size, hex_output=hex_digest)
