Compression algorithms
=======================

.. automodule:: malduck.compression

Every decompressor runs inside a shared bounded transaction: malformed
framing, truncated streams and payloads that would expand past the output
budget raise :class:`malduck.compression.DecompressionError` (a
:class:`RuntimeError` subclass) and the partially produced buffer is
discarded. The budget can be tuned with the ``output_limit`` argument.

aPLib
------

.. autofunction:: malduck.aplib

gzip
------

.. autofunction:: malduck.gzip

lznt1 (RtlDecompressBuffer)
----------------------------

.. autofunction:: malduck.lznt1
