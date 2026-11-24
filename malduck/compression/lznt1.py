from typing import Optional

from .components.lznt1 import decompress_data
from .transaction import DEFAULT_OUTPUT_LIMIT

__all__ = ["Lznt1", "lznt1"]


class Lznt1:
    """
    Implementation of LZNT1 decompression. Allows to decompress data compressed by RtlCompressBuffer

    .. code-block:: python

        from malduck import lznt1

        lznt1(b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot")

    :param buf: Buffer to decompress
    :type buf: bytes
    :param output_limit: Maximum number of bytes that may be produced by the
        decompression transaction (all LZNT1 blocks share the same budget).
        Defaults to
        :data:`malduck.compression.transaction.DEFAULT_OUTPUT_LIMIT`, pass
        ``None`` to disable the budget.
    :type output_limit: int, optional
    :rtype: bytes
    """

    def decompress(
        self, buf: bytes, output_limit: Optional[int] = DEFAULT_OUTPUT_LIMIT
    ) -> bytes:
        return decompress_data(buf, output_limit=output_limit)

    __call__ = decompress


lznt1 = Lznt1()
