"""
Shared decompression transaction primitives.

Every decompressor in :mod:`malduck.compression` shares the same building
blocks:

* :class:`DecompressionError` - a single, consistent failure signal that
  callers (e.g. the carving engine) can catch without knowing the concrete
  format;
* :class:`BoundedOutput` - an in-memory sink that enforces a streaming output
  budget so that a malicious payload which declares a tiny input but keeps
  expanding cannot exhaust the available memory;
* :class:`DecompressionTransaction` - the context that owns the output sink
  and guarantees that a failure releases every partially produced buffer.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

__all__ = [
    "DEFAULT_OUTPUT_LIMIT",
    "DecompressionError",
    "BoundedOutput",
    "DecompressionTransaction",
    "decompression_transaction",
]

#: Default ceiling for a single decompressed payload (32 MiB). This matches
#: the historical aPLib safety bound while covering every legitimate sample.
DEFAULT_OUTPUT_LIMIT: int = 32 * 1024 * 1024


class DecompressionError(RuntimeError):
    """Raised when a decompression transaction cannot be completed.

    This covers malformed framing/control headers, truncated streams and
    exhausted output budgets. It inherits from :class:`RuntimeError` so the
    previously raised ``RuntimeError`` based checks stay valid.
    """


class BoundedOutput:
    """Buffered output sink enforcing a maximum decompressed size.

    Every write is checked against ``limit`` *before* the bytes are appended,
    which keeps the peak memory usage at ``limit`` instead of allowing a
    decompression bomb to grow the buffer without bounds.

    :param limit: Maximum number of bytes that may be produced. ``None``
        disables the budget (kept for explicit opt-in by callers that already
        constrain the input themselves).
    :type limit: int, optional
    """

    __slots__ = ("buffer", "limit")

    def __init__(self, limit: Optional[int] = DEFAULT_OUTPUT_LIMIT) -> None:
        if limit is not None and limit < 0:
            raise ValueError("Output limit must not be negative")
        self.buffer = bytearray()
        self.limit = limit

    def _reserve(self, amount: int) -> None:
        if amount <= 0 or self.limit is None:
            return
        if len(self.buffer) + amount > self.limit:
            raise DecompressionError(
                "Decompressed payload exceeds the output limit of %d bytes "
                "(declared %d bytes, produced at least %d)"
                % (self.limit, amount, len(self.buffer) + amount)
            )

    def write(self, data: bytes) -> int:
        self._reserve(len(data))
        self.buffer.extend(data)
        return len(data)

    def append(self, value: int) -> None:
        self._reserve(1)
        self.buffer.append(value)

    def extend(self, data: bytes) -> None:
        self.write(data)

    def getvalue(self) -> bytes:
        return bytes(self.buffer)

    def __len__(self) -> int:
        return len(self.buffer)

    def __getitem__(self, item):
        return self.buffer[item]

    def byte_at(self, distance: int) -> int:
        """Return the byte produced ``distance`` positions before the end."""
        if distance <= 0 or distance > len(self.buffer):
            raise DecompressionError(
                "Back-reference points outside of the decompressed output"
            )
        return self.buffer[-distance]

    def close(self) -> None:
        # Compatibility shim for code that previously used a BytesIO sink.
        pass


class DecompressionTransaction:
    """Context manager owning a single bounded decompression attempt.

    The transaction gives every decompressor (:class:`Gzip`,
    :class:`Lznt1`, :class:`aPLib`) the same lifecycle:

    1. a :class:`BoundedOutput` sink with an explicit budget is created;
    2. format/control-header validation and streaming decompression happen
       inside the ``with`` block;
    3. on any exception the partially produced output is dropped and the
       original error is propagated (wrapped in
       :class:`DecompressionError` when it is a low-level format error);
    4. on success the buffered payload is returned exactly once.

    :param limit: Maximum decompressed size in bytes.
    :type limit: int, optional
    """

    def __init__(self, limit: Optional[int] = DEFAULT_OUTPUT_LIMIT) -> None:
        self.output = BoundedOutput(limit)

    def __enter__(self) -> BoundedOutput:
        return self.output

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None:
            # Failure cleanup: never hand a partially inflated buffer back.
            self.output.buffer.clear()
            if (
                not issubclass(exc_type, DecompressionError)
                and isinstance(exc_val, Exception)
            ):
                # Normalize low-level format errors onto the shared error
                # type; BaseException (e.g. KeyboardInterrupt) passes through.
                raise DecompressionError(
                    "Decompression transaction failed: %s" % exc_val
                ) from exc_val
        return False


@contextmanager
def decompression_transaction(
    limit: Optional[int] = DEFAULT_OUTPUT_LIMIT,
) -> Iterator[BoundedOutput]:
    """Functional form of :class:`DecompressionTransaction`."""
    transaction = DecompressionTransaction(limit)
    with transaction as output:
        yield output
