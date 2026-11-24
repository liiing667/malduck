# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import gzip as gzip_module
import struct
import zlib

import pytest

from malduck import aplib, gzip, base64, lznt1
from malduck.compression import (
    BoundedOutput,
    DEFAULT_OUTPUT_LIMIT,
    DecompressionError,
    DecompressionTransaction,
)
from malduck.compression.components.aplib import APLib


def test_aplib():
    assert aplib(
        base64("QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA==")
    ) == b"hello world"
    assert aplib(base64("aDhlbI5vIHducuxkAA==")) == b"hello world"
    assert aplib(base64("""
QVAzMhgAAABGAAAAf+p8HwEAEAA5iu7QQacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3/
/IcB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"
    assert aplib(base64("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"
    assert (
        aplib(b'T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00') ==
        b'The quick brown fox jumps over the lazy dog')


def test_gzip():
    assert gzip(base64("eJzLSM3JyVcozy/KSQEAGgsEXQ==")) == b"hello world"
    assert gzip(
        base64("H4sICCGZt1oEAzEtMQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"
    assert gzip(
        base64("H4sICCOZt1oCAzEtOQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"


def test_lznt1():
    assert lznt1(b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot") == b"compressedtestdatacompressedalot"


def test_gzip_output_budget_and_multistream():
    payload = b"hello world"
    # plain zlib and gzip framing
    assert gzip(zlib.compress(payload)) == payload
    assert gzip(gzip_module.compress(payload)) == payload
    # concatenated gzip members and zlib streams stay supported
    assert gzip(
        gzip_module.compress(b"part1") + gzip_module.compress(b"part2")
    ) == b"part1part2"
    assert gzip(
        zlib.compress(b"a") + zlib.compress(b"b") + zlib.compress(b"c")
    ) == b"abc"
    # the budget is shared by every member/stream of the transaction
    with pytest.raises(DecompressionError):
        gzip(
            gzip_module.compress(b"ok") + gzip_module.compress(b"A" * 10000),
            output_limit=128,
        )
    with pytest.raises(DecompressionError):
        gzip(zlib.compress(b"A" * 10000), output_limit=128)
    # exact boundary is accepted, one byte more is rejected
    assert gzip(zlib.compress(b"Z" * 1000), output_limit=1000) == b"Z" * 1000
    with pytest.raises(DecompressionError):
        gzip(zlib.compress(b"Z" * 1001), output_limit=1000)
    # disabling the budget keeps working
    assert gzip(zlib.compress(b"B" * 5000), output_limit=None) == b"B" * 5000


def test_gzip_rejects_malformed_framing():
    payload = b"hello world"
    for bad in (
        b"\x1f\x8b\x08garbage",
        b"\x1f\x8b\x08",
        gzip_module.compress(payload)[:-3],
        zlib.compress(payload)[:-3],
        b"xxxx",
    ):
        with pytest.raises(DecompressionError):
            gzip(bad)
    # DecompressionError is a RuntimeError, so legacy handling still works
    assert issubclass(DecompressionError, RuntimeError)


def test_lznt1_blocks_and_budget():
    # uncompressed control-header variant
    assert lznt1(struct.pack("<H", 0x3002) + b"ABC") == b"ABC"
    # several in-bound blocks inside one transaction
    multi = (
        struct.pack("<H", 0x3002) + b"ABC"
        + struct.pack("<H", 0x3001) + b"DE"
    )
    assert lznt1(multi) == b"ABCDE"
    # compressed block made of plain literals (tag 0x00)
    assert lznt1(
        struct.pack("<H", 0xB008) + b"\x00" + b"ABCDEFGH"
    ) == b"ABCDEFGH"
    # malformed control headers are refused instead of looping/crashing
    with pytest.raises(DecompressionError):
        lznt1(b"\x1a")
    with pytest.raises(DecompressionError):
        lznt1(struct.pack("<H", 0xB010) + b"\x00AB")
    with pytest.raises(DecompressionError):
        lznt1(struct.pack("<H", 0xB003) + b"\x01\x10")
    # output budget shared across blocks
    with pytest.raises(DecompressionError):
        lznt1(struct.pack("<H", 0x3009) + b"0123456789", output_limit=4)
    assert lznt1(
        struct.pack("<H", 0x3009) + b"0123456789", output_limit=10
    ) == b"0123456789"


def test_lznt1_rle_bomb_is_capped():
    # a single self-referential token (offset 1, maximum length) turns a
    # handful of input bytes into a few thousand output bytes
    pointer = 0xFFF
    payload = b"\x02A" + struct.pack("<H", pointer)
    blob = struct.pack("<H", 0xB000 | (len(payload) - 1)) + payload
    with pytest.raises(DecompressionError):
        lznt1(blob, output_limit=1024)


def test_aplib_budget_evidence_and_cleanup():
    packed = base64("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""")
    # default budget still covers the legitimate 1 MiB expansion
    assert len(aplib(packed)) == 1024 * 1024 + 1
    # smaller budgets stop the same payload early
    for limit in (1024, 65536):
        with pytest.raises(DecompressionError):
            aplib(packed, output_limit=limit)
    # AP32 header evidence (declared size) is checked against the budget
    fake = b"AP32" + struct.pack("=IIIII", 24, 4, 0, 10 ** 9, 0) + b"abcd"
    with pytest.raises(DecompressionError):
        aplib(fake, output_limit=1024)
    # a failed transaction never leaks the partially inflated buffer
    sink = BoundedOutput(64)
    with pytest.raises(DecompressionError):
        with DecompressionTransaction(64) as output:
            assert output is sink
            APLib(packed, strict=True, destination=output).depack()
    assert len(sink) == 0


def test_aplib_strict_header_evidence():
    header_sample = base64(
        "QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA=="
    )
    assert aplib(header_sample, headerless=False) == b"hello world"
    corrupted_crc = bytearray(header_sample)
    corrupted_crc[12] ^= 0xFF
    with pytest.raises(DecompressionError):
        aplib(bytes(corrupted_crc), headerless=False)
    corrupted_size = bytearray(header_sample)
    corrupted_size[16] ^= 0xFF
    with pytest.raises(DecompressionError):
        aplib(bytes(corrupted_size), headerless=False)


def test_default_limit_is_sane():
    assert DEFAULT_OUTPUT_LIMIT >= 1024 * 1024
