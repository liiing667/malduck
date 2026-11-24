# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

__all__ = ["rol", "ror", "align", "align_down"]


def rol(value: int, count: int, bits: int = 32) -> int:
    """
    Bitwise rotate left

    :param value: Value to rotate
    :param count: Number of bits to rotate
    :param bits: Bit-length of rotated value (default: 32-bit, DWORD)

    .. seealso::

       :py:meth:`malduck.ints.IntType.rol`

    """
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("bits must be an integer")
    if bits <= 0:
        raise ValueError("bits must be greater than 0")
    count %= bits
    mask = (1 << bits) - 1
    value &= mask
    if count == 0:
        return value
    return ((value << count) | (value >> (bits - count))) & mask


def ror(value: int, count: int, bits: int = 32) -> int:
    """
    Bitwise rotate right

    :param value: Value to rotate
    :param count: Number of bits to rotate
    :param bits: Bit-length of rotated value (default: 32-bit, DWORD)

    .. seealso::

       :py:meth:`malduck.ints.IntType.ror`

    """
    return rol(value, -count, bits)


def align(value: int, round_to: int) -> int:
    """
    Rounds value up to provided alignment
    """
    if not isinstance(round_to, int) or isinstance(round_to, bool):
        raise TypeError("round_to must be an integer")
    if round_to <= 0:
        raise ValueError("round_to must be greater than 0")
    return ((value - 1) // round_to + 1) * round_to


def align_down(value: int, round_to: int) -> int:
    """
    Rounds value down to provided alignment
    """
    if not isinstance(round_to, int) or isinstance(round_to, bool):
        raise TypeError("round_to must be an integer")
    if round_to <= 0:
        raise ValueError("round_to must be greater than 0")
    return (value // round_to) * round_to
