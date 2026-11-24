# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
from __future__ import absolute_import

import io
import zlib
from gzip import GzipFile
from typing import Optional

from .transaction import (
    DEFAULT_OUTPUT_LIMIT,
    DecompressionError,
    DecompressionTransaction,
)

__all__ = ["gzip", "Gzip"]

#: Size of a single streamed read (kept well below the output budget).
_CHUNK_SIZE = 64 * 1024


class Gzip:
    r"""
    gzip/zlib decompression

    .. code-block:: python

        from malduck import gzip, unhex

        # zlib decompression
        gzip(unhex(b'789ccb48cdc9c95728cf2fca4901001a0b045d'))
        # gzip decompression (detected by 1f8b08 prefix)
        gzip(unhex(b'1f8b08082199b75a0403312d3100cb48cdc9c95728cf2fca49010085114a0d0b000000'))

    :param buf: Buffer to decompress
    :type buf: bytes
    :param output_limit: Maximum number of bytes that may be produced by the
        whole decompression transaction (concatenated gzip members / zlib
        streams included). Defaults to
        :data:`malduck.compression.transaction.DEFAULT_OUTPUT_LIMIT`, pass
        ``None`` to disable the budget.
    :type output_limit: int, optional
    :rtype: bytes
    """

    def decompress(
        self, buf: bytes, output_limit: Optional[int] = DEFAULT_OUTPUT_LIMIT
    ) -> bytes:
        with DecompressionTransaction(output_limit) as output:
            if buf.startswith(b"\x1f\x8b\x08"):
                # GzipFile transparently walks every concatenated member, so
                # multi-member payloads keep working while each streamed
                # chunk is checked against the shared output budget.
                try:
                    with GzipFile(fileobj=io.BytesIO(buf)) as gz:
                        while True:
                            chunk = gz.read(_CHUNK_SIZE)
                            if not chunk:
                                break
                            output.write(chunk)
                except (EOFError, OSError, zlib.error) as exc:
                    raise DecompressionError(
                        "Malformed gzip payload: %s" % exc
                    ) from exc
            else:
                # zlib streams may also be concatenated; each decompressobj
                # consumes a single stream and reports the leftover bytes via
                # unused_data, so loop until the whole input is accounted for.
                remaining = buf
                while remaining:
                    decompressor = zlib.decompressobj()
                    try:
                        # Feed the stream in bounded pieces so the produced
                        # output never exceeds the transaction budget; the
                        # decompressor keeps track of the stream boundary and
                        # exposes the tail belonging to the next stream.
                        view = memoryview(remaining)
                        pos = 0
                        while pos < len(view):
                            end = min(pos + _CHUNK_SIZE, len(view))
                            output.write(
                                decompressor.decompress(view[pos:end])
                            )
                            pos = end
                        output.write(decompressor.flush())
                        if not decompressor.eof:
                            raise DecompressionError(
                                "Malformed zlib payload: truncated stream"
                            )
                        remaining = decompressor.unused_data
                    except zlib.error as exc:
                        raise DecompressionError(
                            "Malformed zlib payload: %s" % exc
                        ) from exc
            return output.getvalue()

    __call__ = decompress


gzip = Gzip()
