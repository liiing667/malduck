# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""Decompression support for the LZNT1 compression algorithm.

Reference:
http://msdn.microsoft.com/en-us/library/jj665697.aspx
(2.5 LZNT1 Algorithm Details)

https://github.com/libyal/reviveit/
https://github.com/sleuthkit/sleuthkit/blob/develop/tsk/fs/ntfs.c
"""
import array
import struct
from typing import Optional

from ..transaction import (
    DEFAULT_OUTPUT_LIMIT,
    DecompressionError,
    DecompressionTransaction,
)

__all__ = ["decompress_data"]


def get_displacement(offset: int) -> int:
    """Calculate the displacement."""
    result = 0
    while offset >= 0x10:
        offset >>= 1
        result += 1

    return result


DISPLACEMENT_TABLE = array.array("B", [get_displacement(x) for x in range(8192)])

COMPRESSED_MASK = 1 << 15
SIGNATURE_MASK = 3 << 12
SIZE_MASK = (1 << 12) - 1
TAG_MASKS = [(1 << i) for i in range(0, 8)]


def decompress_data(
    cdata: bytes, output_limit: Optional[int] = DEFAULT_OUTPUT_LIMIT
) -> bytes:
    """Decompresses the data.

    The whole operation runs inside a :class:`DecompressionTransaction`:
    every control (block) header is validated against the remaining input,
    every emitted byte (including bytes produced by a back-reference) is
    charged against the shared output budget and any failure discards the
    partially decompressed buffer.

    :param cdata: LZNT1 compressed buffer
    :type cdata: bytes
    :param output_limit: Maximum decompressed size in bytes
    :type output_limit: int, optional
    :rtype: bytes
    """
    if not isinstance(cdata, (bytes, bytearray, memoryview)):
        raise TypeError("Compressed data must be a bytes-like object")
    cdata = bytes(cdata)

    with DecompressionTransaction(output_limit) as output_fd:
        offset = 0

        while offset < len(cdata):
            uncompressed_chunk_offset = len(output_fd)

            # A block header always consumes two bytes.
            if offset + 2 > len(cdata):
                raise DecompressionError(
                    "Truncated LZNT1 block header at offset %d" % offset
                )

            block_header = struct.unpack_from("<H", cdata, offset)[0]

            if block_header & SIGNATURE_MASK != SIGNATURE_MASK:
                # End of the LZNT1 stream: the remaining bytes are padding.
                break

            size = block_header & SIZE_MASK
            block_end = offset + size + 3

            # A declared block must be fully contained in the input.
            if block_end > len(cdata):
                raise DecompressionError(
                    "LZNT1 block at offset %d declares %d bytes but only %d "
                    "remain" % (offset, block_end - offset, len(cdata) - offset)
                )

            data_offset = offset + 2

            if block_header & COMPRESSED_MASK:
                while data_offset < block_end:
                    header = cdata[data_offset]
                    data_offset += 1

                    for mask in TAG_MASKS:
                        if data_offset >= block_end:
                            break

                        if header & mask:
                            if data_offset + 2 > block_end:
                                raise DecompressionError(
                                    "Truncated LZNT1 back-reference at "
                                    "offset %d" % data_offset
                                )
                            pointer = struct.unpack_from(
                                "<H", cdata, data_offset
                            )[0]
                            data_offset += 2

                            chunk_position = (
                                len(output_fd) - uncompressed_chunk_offset - 1
                            )
                            if not 0 <= chunk_position < len(DISPLACEMENT_TABLE):
                                raise DecompressionError(
                                    "LZNT1 chunk grew beyond the supported "
                                    "window of %d bytes"
                                    % len(DISPLACEMENT_TABLE)
                                )
                            displacement = DISPLACEMENT_TABLE[
                                chunk_position
                            ]

                            symbol_offset = (
                                pointer >> (12 - displacement)
                            ) + 1
                            symbol_length = (
                                pointer & (0xFFF >> displacement)
                            ) + 3

                            # Copy byte by byte so overlapping references
                            # (the classic RLE expansion trick used by
                            # decompression bombs) are charged one byte at a
                            # time against the output budget. byte_at()
                            # validates that the reference points at already
                            # produced data.
                            for _ in range(symbol_length):
                                output_fd.append(
                                    output_fd.byte_at(symbol_offset)
                                )

                        else:
                            output_fd.append(cdata[data_offset])
                            data_offset += 1
            else:
                # Block is not compressed: exactly size + 1 literal bytes.
                output_fd.write(cdata[data_offset:block_end])

            offset = block_end

        return output_fd.getvalue()
