"""
Algorithm and test cases from FIPS Publication 197, Specification for the 
Advanced Encryption Standard (AES), 
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

def word_add(a, b):
    """Returns the sum of four-byte words A and B by letting each word 
    represent a polynomial of degree 3 with coefficients in GF(2^8). A and B 
    should be sequences of bytes."""
    return bytes(ai ^ bi for ai in a for bi in b)

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