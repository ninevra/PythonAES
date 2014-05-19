"""
Algorithm, data and test cases from FIPS Publication 197, Specification for 
the Advanced Encryption Standard (AES), 
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

_m = 0x11b # equivalent to x^8 + x^4 + x^3 + x + 1

def byte_mul(a, b):
    """Returns the product of (int) bytes A and B in GF(2^8) modulo _M.

    >>> hex(byte_mul(0x57, 0x13))
    '0xfe'
    """
    ret = 0
    while b != 0:
        if b & 1 != 0:
            ret ^= a
        a = byte_mulx(a)
        b >>= 1
    return ret

def byte_mulx(b):
    """Returns the product of the polynomial representation of (int) byte
    B and x in GF(2^8).

    >>> x = byte_mulx(0x57)
    >>> x == 0xae
    True
    >>> x = byte_mulx(x)
    >>> x == 0x47
    True
    >>> x = byte_mulx(x)
    >>> x == 0x8e
    True
    >>> byte_mulx(x) == 0x07
    True
    """
    return b << 1 if b & 128 == 0 else (b << 1) ^ _m

def xor_bytes(a, b):
    """Returns the pointwise xor of byte sequences A and B. For four-byte 
    words, this represents the sum."""
    return list(ai ^ bi for (ai, bi) in zip(a, b))

def word_mul(a, b):
    """Returns the product of four-byte words A and B mod x^4 + 1, 
    calculated by representing words [a0, a1, a2, a3] as polynomials 
    a3*x^3 + a2*x^2 + a1*x + a0. A and B should be sequences of bytes. 

    >>> word_mul(bytes.fromhex('02010103'), bytes.fromhex('0e090d0b'))
    (1, 0, 0, 0)
    >>> word_mul(bytes.fromhex('fd08ab00'), (1,0,0,0))
    (253, 8, 171, 0)
    >>> word_mul(bytes.fromhex('fd08ab00'), (0,0,0,0))
    (0, 0, 0, 0)
    """
    return (byte_mul(a[0], b[0]) ^ byte_mul(a[3], b[1]) ^ 
                byte_mul(a[2], b[2]) ^ byte_mul(a[1], b[3]),
            byte_mul(a[1], b[0]) ^ byte_mul(a[0], b[1]) ^ 
                byte_mul(a[3], b[2]) ^ byte_mul(a[2], b[3]),
            byte_mul(a[2], b[0]) ^ byte_mul(a[1], b[1]) ^ 
                byte_mul(a[0], b[2]) ^ byte_mul(a[3], b[3]),
            byte_mul(a[3], b[0]) ^ byte_mul(a[2], b[1]) ^
                byte_mul(a[1], b[2]) ^ byte_mul(a[0], b[3]))

_block_size = 4 # words per block of ciphertext or plaintext

_s_box = [
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
]

_inv_s_box = [
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

def rcon_gen():
    rcon = [1,0,0,0]
    while True:
        yield rcon
        rcon[0] = byte_mulx(rcon[0])

def key_expand(key):
    """Takes the encryption KEY as a sequence of bytes and returns a key 
    schedule as a sequence of _BLOCK_SIZE * (num_rounds + 1) words.
    """
    key_len = len(key) // 4 # words in the key
    num_rounds = key_len + 6
    schedule = [key[4*i:4*(i+1)] for i in range(key_len)]
    rcon = rcon_gen()
    while len(schedule) < _block_size * (num_rounds + 1):
        temp = schedule[-1]
        if len(schedule) % key_len == 0:
            temp = xor_bytes(sub_bytes(rot_word(temp)), next(rcon))
        elif key_len == 8 and len(schedule) % key_len == 4:
            temp = sub_bytes(temp)
        schedule.append(xor_bytes(schedule[-key_len], temp))
    return schedule

_rotators = ((0,0,0,1), (0,0,1,0), (0,1,0,0))

def rot_word(word, n=1):
    """Returns the result of rotating WORD N places to the left.
    >>> rot_word((1,2,4,8))
    (2, 4, 8, 1)
    >>> rot_word((1,2,4,8), 2)
    (4, 8, 1, 2)
    >>> rot_word((1,2,4,8), 3)
    (8, 1, 2, 4)"""
    return word_mul(word, _rotators[(n % 4) - 1])

def join_wds(wds):
    ret = []
    for wd in wds:
        ret.extend(wd)
    return ret

def round_key(key_schedule, rd):
    return join_wds(key_schedule[rd * _block_size : (rd + 1) * _block_size])

def aes_cipher(plain_block, key):
    """Returns the ciphertext version of PLAIN_BLOCK, using KEY.

    >>> key = (43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60)
    >>> pt = bytes.fromhex('32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34')
    >>> wdhex(aes_cipher(pt, key))
    '39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32'"""
    key_len = len(key) // 4
    num_rounds = key_len + 6
    key_schedule = key_expand(key)
    state = add_round_key(plain_block, round_key(key_schedule, 0))
    for rd in range(1, num_rounds):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key(key_schedule, rd))
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key(key_schedule, num_rounds))
    return state

def sub_bytes(state):
    """Returns the result of substituing each byte in the 1D array STATE 
    with the corresponding S-box value."""
    return [_s_box[i] for i in state]

def shift_rows(state):
    """Treating the 1D input array as a 4x4 column-major array, returns the 
    result of rotating each row to the left a number of places equal to its 
    index."""
    ret = list(state)
    for i in range(1, 4):
        ret[i::4] = rot_word(ret[i::4], i)
    return ret

_col_mixin = (2, 1, 1, 3)

def mix_columns(state):
    """Treating the 1D input array as a 4x4 column-major array, returns the 
    result of multiplying each column by _COL_MIXIN."""
    return word_mul(state[:4], _col_mixin) + word_mul(state[4:8], _col_mixin) \
        + word_mul(state[8:12], _col_mixin) + word_mul(state[12:16], _col_mixin)

def add_round_key(state, key):
    """Return the result of pointwise adding KEY to STATE"""
    return xor_bytes(state[:4], key[:4]) + xor_bytes(state[4:8], key[4:8]) + \
        xor_bytes(state[8:12], key[8:12]) + xor_bytes(state[12:], key[12:])

def aes_inv_cipher(cipher_block, key):
    """Return the plaintext version of CIPHER_BLOCK, using KEY, by the simple 
    inverse cipher.
    >>> key = (43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60)
    >>> ct = bytes.fromhex('39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32')
    >>> wdhex(aes_inv_cipher(ct, key))
    '32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34'"""
    key_len = len(key) // 4
    num_rounds = key_len + 6
    key_schedule = key_expand(key)
    state = add_round_key(cipher_block, round_key(key_schedule, num_rounds))
    for rd in range(num_rounds - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_key(key_schedule, rd))
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_key(key_schedule, 0))
    return state

def inv_shift_rows(state):
    """Treating the 1D array STATE as a 4x4 column-major array, return the 
    result of right-shifting each row by an amount equal to its index."""
    ret = list(state)
    for i in range(1, 4):
        ret[i::4] = rot_word(ret[i::4], 4 - i)
    return ret

def inv_sub_bytes(state):
    """Return the result of applying the inverse S-box to each byte of STATE.
    """
    return [_inv_s_box[i] for i in state]

_inv_col_mixin = (0x0e, 9, 0x0d, 0x0b)

def inv_mix_columns(state):
    """Treating the 1D array STATE as a 4x4 column-major array, return the 
    result of multiplying each column by the inverse of the column mixin."""
    return word_mul(state[:4], _inv_col_mixin) + word_mul(state[4:8], _inv_col_mixin) + \
        word_mul(state[8:12], _inv_col_mixin) + word_mul(state[12:], _inv_col_mixin)

def wdhex(wd):
    return ' '.join(hex(i)[2:].rjust(2,'0') for i in wd)

def wdshex(wds):
    return ' '.join(wdhex(wd) for wd in wds)

def aes_eq_inv_cipher(cipher_block, key):
    """Return the plaintext corresponding to CIPHER_BLOCK, using KEY, by the 
    equivalent inverse cipher.
    >>> key = (43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60)
    >>> ct = bytes.fromhex('39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32')
    >>> wdhex(aes_inv_cipher(ct, key))
    '32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34'"""
    key_len = len(key) // 4
    num_rounds = key_len + 6
    key_schedule = key_expand(key)
    state = add_round_key(cipher_block, round_key(key_schedule, num_rounds))
    for rd in range(num_rounds - 1, 0, -1):
        state = inv_sub_bytes(state)
        state = inv_shift_rows(state)
        state = inv_mix_columns(state)
        state = add_round_key(state, inv_mix_columns(round_key(key_schedule, rd)))
    state = inv_sub_bytes(state)
    state = inv_shift_rows(state)
    state = add_round_key(state, round_key(key_schedule, 0))
    return state

def cbc_encrypt(cipher, key, iv, plaintext):
    """Takes a CIPHER method and a PLAINTEXT sequence of bytes and applies the 
    cipher in the cipher block chaining mode with the given initialization
    vector IV."""
    ct = bytearray(cipher(xor_bytes(iv, plaintext[:16]), key))
    for i in range(16, len(plaintext), 16):
        ct.extend(cipher(xor_bytes(ct[-16:], plaintext[i:i+16]), key))
    return ct

def cbc_decrypt(uncipher, key, iv, ciphertext):
    """Uses the deciphering method UNCIPHER, KEY, and IV to decrypt 
    CIPHERTEXT."""
    pt = bytearray(xor_bytes(uncipher(ciphertext[:16], key), iv))
    for i in range(16, len(ciphertext), 16):
        pt.extend(xor_bytes(uncipher(ciphertext[i:i+16], key), ciphertext[i-16:i]))
    return pt