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