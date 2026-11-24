import logging
import struct
from binascii import crc32
from typing import Optional

from .components.aplib import APLib
from .transaction import (
    DEFAULT_OUTPUT_LIMIT,
    DecompressionError,
    DecompressionTransaction,
)

__all__ = ["aPLib", "aplib"]

log = logging.getLogger(__name__)


class aPLib:
    r"""
    aPLib decompression

    .. code-block:: python

        from malduck import aplib

        # Headerless compressed buffer
        aplib(b'T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00')
        # Header included
        aplib(b'AP32\x18\x00\x00\x00\r\x00\x00\x00\xbc\x9ab\x9b\x0b\x00\x00\x00\x85\x11J\rh8el\x8eo wnr\xecd\x00')

    :param buf: Buffer to decompress
    :type buf: bytes
    :param headerless: Force headerless decompression (don't perform 'AP32' magic detection)
    :type headerless: bool (default: `True`)
    :param output_limit: Maximum number of bytes that may be produced by the
        decompression transaction. The size declared in the AP32 header is
        validated against the same budget. Defaults to
        :data:`malduck.compression.transaction.DEFAULT_OUTPUT_LIMIT`, pass
        ``None`` to disable the budget.
    :type output_limit: int, optional
    :rtype: bytes
    """

    def decompress(
        self,
        buf: bytes,
        headerless: bool = True,
        output_limit: Optional[int] = DEFAULT_OUTPUT_LIMIT,
    ) -> Optional[bytes]:
        packed_size = None
        packed_crc = None
        orig_size = None
        orig_crc = None
        strict = not headerless

        if buf.startswith(b"AP32") and len(buf) >= 24:
            # buf has an aPLib header
            (
                header_size,
                packed_size,
                packed_crc,
                orig_size,
                orig_crc,
            ) = struct.unpack_from("=IIIII", buf, 4)
            if header_size + packed_size > len(buf):
                raise DecompressionError(
                    "aPLib header declares more packed bytes than available"
                )
            if (
                orig_size is not None
                and output_limit is not None
                and orig_size > output_limit
            ):
                raise DecompressionError(
                    "aPLib header declares an unpacked size of %d bytes which "
                    "exceeds the output limit of %d" % (orig_size, output_limit)
                )
            buf = buf[header_size : header_size + packed_size]

        if strict:
            if packed_size is not None and packed_size != len(buf):
                raise DecompressionError("Packed buf size is incorrect")
            if packed_crc is not None and packed_crc != crc32(buf):
                raise DecompressionError("Packed buf checksum is incorrect")

        with DecompressionTransaction(output_limit) as output:
            result = APLib(buf, strict=strict, destination=output).depack()

            if strict:
                if orig_size is not None and orig_size != len(result):
                    raise DecompressionError("Unpacked buf size is incorrect")
                if orig_crc is not None and orig_crc != crc32(result):
                    raise DecompressionError("Unpacked buf checksum is incorrect")

        return result

    __call__ = decompress


aplib = aPLib()
