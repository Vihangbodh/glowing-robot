# -*- coding: utf-8 -*-
"""
Author: Goddard Guryon
In this, I have implemented an AES cipher (symmetric cipher), based on AES-Python
(https://github.com/bozhu/AES-Python). I was interested in understanding the mathematics behind the
Rijndael algorithm, so I also studied a bit from Brandon Sterne's PyAES implementation tutorial
(https://brandon.sternefamily.net/2007/06/aes-tutorial-python-implementation/), make sure to check out
both of these links for original implementation :)
"""

import codecs
from glowing_signature import _generate_prime as key_maker

# initialize the variables
# the S-box lookup table is used for byte substitution
_S_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# inverse table for the decryption function
_invert_S_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# initial round constants
_round_constants = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
)


def mix(x):
    return (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else (x << 1)


# I have added the backend functions in order of execution to make understanding them easier
def _text_to_matrix(text):
    # before encrypting, we need to convert the plain text into a matrix
    matrix = []
    # for a 4x4 matrix, run the loop 16 times
    for i in range(16):
        # convert the text into a byte object
        entry = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            # make a new row
            matrix.append([entry])
        else:
            # we already are in the row, just append to it
            # added integer division (//) to stop PyCharm's static code analysis from bugging me
            matrix[i // 4].append(entry)
    return matrix


# before starting encryption, create the round keys from our master key
def _make_round_keys(master_key):
    # convert the key into a matrix
    round_keys = _text_to_matrix(master_key)
    for i in range(4, 4 * 11):
        # add empty list to append to
        round_keys.append([])

        # if we are at the first column of the row
        if i % 4 == 0:
            # calculate the first entry of the row and add it to the matrix
            entry = round_keys[i - 4][0] ^ _S_box[round_keys[i - 1][1]] ^ _round_constants[i // 4]
            round_keys[i].append(entry)

            # calculate rest of the entries of the row and add them
            for j in range(1, 4):
                entry = round_keys[i - 4][j] ^ _S_box[round_keys[i - 1][(j + 1) % 4]]
                round_keys[i].append(entry)
        else:
            for j in range(4):
                entry = round_keys[i - 4][j] ^ round_keys[i - 1][j]
                round_keys[i].append(entry)
    return round_keys


def _add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]


def _substitute_bytes(sub):
    for i in range(4):
        for j in range(4):
            sub[i][j] = _S_box[sub[i][j]]


def _invert_substitute_bytes(sub):
    for i in range(4):
        for j in range(4):
            sub[i][j] = _invert_S_box[sub[i][j]]


def _shift_rows(matrix):
    # after substituting the bytes, we shift the rows of some entries in the matrix

    # the first row stays the same, so no code for that
    # the second row entries are shifted left by one unit
    matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[1][1], matrix[2][1], matrix[3][1], matrix[0][1]
    # the third row entries are shifted left by two units
    matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
    # the final row entries are shifted left by three units
    matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[3][3], matrix[0][3], matrix[1][3], matrix[2][3]


def _invert_shift_rows(matrix):
    # inverse of shifting rows for decryption

    # the first row stays the same, so no code for that
    # the second row entries are shifted right by one unit
    matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[3][1], matrix[0][1], matrix[1][1], matrix[2][1]
    # the third row entries are shifted right by two units
    matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
    # the final row entries are shifted right by three units
    matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[1][3], matrix[2][3], matrix[3][3], matrix[0][3]


def _mix_columns(matrix):
    # after shifting the rows, let's mix the columns

    # iterate over each column
    for i in range(4):
        # mix the values (I ain't sure I understand this part)
        variable_x = matrix[i][0] ^ matrix[i][1] ^ matrix[i][2] ^ matrix[i][3]
        temp_row_0 = matrix[i][0]
        matrix[i][0] ^= variable_x ^ mix(matrix[i][0] ^ matrix[i][1])
        matrix[i][1] ^= variable_x ^ mix(matrix[i][1] ^ matrix[i][2])
        matrix[i][2] ^= variable_x ^ mix(matrix[i][2] ^ matrix[i][3])
        matrix[i][3] ^= variable_x ^ mix(matrix[i][3] ^ temp_row_0)


def _invert_mix_columns(matrix):
    # inverse of mixing columns for decryption

    # I'm pretty sure I don't understand this part, but it solves the matrix
    # in such a way that then mixing the columns just undoes the original mixing
    for i in range(4):
        variable_1 = mix(mix(matrix[i][0] ^ matrix[i][2]))
        variable_2 = mix(mix(matrix[i][1] ^ matrix[i][3]))
        matrix[i][0] ^= variable_1
        matrix[i][1] ^= variable_2
        matrix[i][2] ^= variable_1
        matrix[i][3] ^= variable_2

    # mix the columns of the matrix we made
    _mix_columns(matrix)


def _matrix_to_text(matrix):
    # after all operations, convert the matrix back to text and return it
    return_text = 0
    for i in range(4):
        for j in range(4):
            return_text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return return_text


def aes_encrypt(master_key: hex, plain_text: hex):
    """
    Frontend AES Encryption Function
    :param master_key: the key to be used for encryption
    :param plain_text: the text to be encrypted, in integer form
    :return: encrypted text, in integer form
    """
    # convert the plain text into matrix
    plain_state = _text_to_matrix(plain_text)

    # create the initial round key
    round_keys = _make_round_keys(master_key)

    # add the round key of first round
    _add_round_key(plain_state, round_keys[:4])

    # run the encryption loop
    for i in range(1, 10):
        # substitute the bytes from the lookup table
        _substitute_bytes(plain_state)

        # shift the rows in the matrix
        _shift_rows(plain_state)

        # mix the columns in the matrix
        _mix_columns(plain_state)

        # add the round key of this round
        _add_round_key(plain_state, round_keys[4 * i:4 * (i + 1)])

    # final byte substitution
    _substitute_bytes(plain_state)

    # final row shifting
    _shift_rows(plain_state)

    # column mixing not required this time
    # final round key addition
    _add_round_key(plain_state, round_keys[40:])

    # convert this to plain text format and return it
    return _matrix_to_text(plain_state)


def aes_decrypt(master_key: hex, cipher_text: hex):
    """
    Frontend AES Decryption Function
    :param master_key: the key to be used for decryption (int)
    :param cipher_text: the text to be decrypted, in integer form
    :return: the decrypted text, in integer form
    """
    # it is basically the encryption function but it reverse order, so I haven't added separate comments for this one
    cipher_state = _text_to_matrix(cipher_text)
    round_keys = _make_round_keys(master_key)
    _add_round_key(cipher_state, round_keys[40:])
    _invert_shift_rows(cipher_state)
    _invert_substitute_bytes(cipher_state)
    for i in range(9, 0, -1):
        _add_round_key(cipher_state, round_keys[4 * i:4 * (i + 1)])
        _invert_mix_columns(cipher_state)
        _invert_shift_rows(cipher_state)
        _invert_substitute_bytes(cipher_state)
    _add_round_key(cipher_state, round_keys[:4])
    return _matrix_to_text(cipher_state)


def demo_everything():
    # the procedure for converting simple text into AES-compatible format turned out to be so complex for me
    # that I have added explanatory comments to this code as well XD

    # take message and key input (can easily convert it to extract key from a file)
    text = input("Enter the message to be encrypted: ")
    key = int(input("Enter the master key to encrypt the message: ") or -1)

    # if no key is provided, create a key from the code in the `glowing_signature` script file
    if key == -1:
        print("No key provided! Generating a default master key...")

        # no need to waste computing power on generating a demo key in the range 2^1024, so I set the keysize to
        # be in the range of 2^50 which gives an estimated keysize of up to 15 bytes
        key = key_maker(keysize=50)
        print("Master key:\n", key)

    # the algorithm only works for 16-bit long integers, so convert the message into that format
    message = [int.from_bytes(
        text[i:i + 16].encode('ascii'),
        'big') for i in range(0, len(text), 16)]
    print("Encrypting the message...")

    # encrypt all those 16-bit long integers
    encrypted = [aes_encrypt(key, chunk) for chunk in message]

    # to print, merge all encrypted chunks into one big encrypted integer
    print("Encrypted the message to:\n", ''.join(
        str(chunk) for chunk in encrypted))
    print("Decrypting the message...")

    # decrypt all chunks, then convert them back into text form and merge them into the original message
    decrypted = [codecs.decode(
        codecs.decode(
            hex(aes_decrypt(key, chunk))[2:],
            'hex'),
        'ascii') for chunk in encrypted]
    print("Decrypted the message to:\n", ''.join(decrypted))


demo_everything()
