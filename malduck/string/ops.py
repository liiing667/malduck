# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import binascii
import codecs
from base64 import b64decode, b64encode
from typing import (
    Any,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

__all__ = [
    "asciiz",
    "chunks_iter",
    "chunks",
    "utf16z",
    "enhex",
    "unhex",
    "uleb128",
    "Base64",
    "Padding",
    "Unpadding",
    "base64",
    "pad",
    "pkcs7",
    "unpad",
    "unpkcs7",
    "StringResult",
    "DecodedString",
    "StringDecodeResult",
    "ULEB128Result",
    "ULEB128_MAX_BYTES",
    "ULEB128_MAX_LENGTH",
]

T = TypeVar("T", bound=Sequence)

# ULEB128 values used by malware analysis are normally at most 64-bit.  The
# encoding itself has no delimiter other than the final byte, so an attacker
# can otherwise force a caller to build an arbitrarily large integer from a
# malicious dump.  Ten bytes are enough for the full unsigned 64-bit range.
ULEB128_MAX_BYTES = 10
ULEB128_MAX_LENGTH = ULEB128_MAX_BYTES


class StringResult(bytes):
    """
    Decoded bytes together with the evidence used to produce them.

    It is a :class:`bytes` subclass, so the historical API keeps returning
    bytes and existing callers continue to work.  The extra attributes make
    the encoding, the consumed range and the decode outcome explicit instead
    of requiring callers to infer them from the returned value.
    """

    def __new__(
        cls,
        value: bytes,
        *,
        encoding: Optional[str] = None,
        offset: int = 0,
        consumed: Optional[int] = None,
        terminated: bool = False,
        status: str = "ok",
        terminator: Optional[bytes] = None,
        raw: Optional[bytes] = None,
        body: Optional[bytes] = None,
        error: Optional[BaseException] = None,
        **extra: Any,
    ) -> "StringResult":
        obj = super().__new__(cls, value)
        if consumed is None:
            consumed = len(value)
        obj.encoding = encoding
        obj.codec = encoding
        obj.offset = offset
        obj.caller_offset = offset
        obj.start = offset
        obj.read_start = offset
        obj.consumed = consumed
        obj.length = consumed
        obj.read_length = consumed
        obj.end = offset + consumed
        obj.read_end = obj.end
        obj.terminated = terminated
        obj.complete = terminated
        obj.incomplete = not terminated
        obj.status = status
        obj.decode_state = status
        obj.state = status
        obj.terminator = terminator
        obj.raw = raw if raw is not None else bytes(value)
        obj.source = obj.raw
        obj.body = body if body is not None else bytes(value)
        obj.input_range = (0, len(obj.raw))
        obj.buffer_range = obj.input_range
        obj.available_range = (offset, len(obj.raw))
        obj.error = error
        obj.decode_error = error
        obj.error_message = str(error) if error is not None else None
        obj.success = status == "ok"
        obj.decoded = status == "ok"
        obj.ok = status == "ok"
        obj.output_encoding = None
        obj.body_range = (offset, offset + len(obj.body))
        obj.value_range = obj.body_range
        obj.output_range = (0, len(value))
        if terminator is not None:
            obj.terminator_range = (
                offset + len(obj.body),
                offset + len(obj.body) + len(terminator),
            )
        else:
            obj.terminator_range = None
        obj.string_range = obj.value_range
        for key, item in extra.items():
            setattr(obj, key, item)
        return obj

    @property
    def value(self) -> bytes:
        """The decoded value as plain :class:`bytes`."""
        return bytes(self)

    @property
    def read_range(self) -> Tuple[int, int]:
        """Inclusive start/exclusive end of the bytes consumed by the decoder."""
        return self.start, self.end

    @property
    def value_length(self) -> int:
        return len(self)

    @property
    def valid(self) -> bool:
        return self.status == "ok"

    def with_offset(self, offset: int) -> "StringResult":
        """Return the same value/evidence rebased to a caller-provided offset."""
        extra = {
            key: value
            for key, value in self.__dict__.items()
            if key
            not in {
                "encoding",
                "codec",
                "offset",
                "caller_offset",
                "start",
                "read_start",
                "consumed",
                "length",
                "read_length",
                "end",
                "read_end",
                "terminated",
                "complete",
                "incomplete",
                "status",
                "decode_state",
                "state",
                "terminator",
                "raw",
                "source",
                "body",
                "input_range",
                "buffer_range",
                "available_range",
                "error",
                "decode_error",
                "error_message",
                "success",
                "decoded",
                "ok",
                "value_range",
                "body_range",
                "output_range",
                "terminator_range",
                "string_range",
                "value",
                "read_range",
                "value_length",
                "valid",
            }
        }
        return StringResult(
            bytes(self),
            encoding=self.encoding,
            offset=offset,
            consumed=self.consumed,
            terminated=self.terminated,
            status=self.status,
            terminator=self.terminator,
            raw=self.raw,
            body=self.body,
            error=self.error,
            **extra,
        )


class ULEB128Result(tuple):
    """
    Historical ``(consumed, value)`` tuple with explicit read evidence.

    ``consumed`` is an absolute end offset (just like the historical return
    value), so a caller can use it directly as the next offset.
    """

    def __new__(
        cls,
        consumed: int,
        value: int,
        *,
        offset: int = 0,
        raw: bytes = b"",
    ) -> "ULEB128Result":
        obj = super().__new__(cls, (consumed, value))
        obj.offset = offset
        obj.caller_offset = offset
        obj.start = offset
        obj.read_start = offset
        obj.end = consumed
        obj.read_end = consumed
        obj.consumed = consumed
        obj.size = consumed - offset
        obj.length = obj.size
        obj.read_length = obj.size
        obj.value = value
        obj.encoding = "uleb128"
        obj.codec = "uleb128"
        obj.terminated = True
        obj.complete = True
        obj.incomplete = False
        obj.status = "ok"
        obj.decode_state = "ok"
        obj.state = "ok"
        obj.success = True
        obj.decoded = True
        obj.ok = True
        obj.output_encoding = None
        obj.raw = raw
        obj.source = raw
        obj.input_range = (0, len(raw))
        obj.buffer_range = obj.input_range
        obj.available_range = (offset, len(raw))
        obj.error = None
        obj.decode_error = None
        obj.error_message = None
        return obj

    @property
    def read_range(self) -> Tuple[int, int]:
        return self.start, self.end


def _as_bytes(s: Union[bytes, bytearray, memoryview]) -> bytes:
    if isinstance(s, bytes):
        return s
    if isinstance(s, (bytearray, memoryview)):
        return bytes(s)
    raise TypeError("expected a bytes-like object")


def _check_offset(offset: int, length: int) -> int:
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError("offset must be an integer")
    if offset < 0 or offset > length:
        raise ValueError("offset is outside of the buffer")
    return offset


def asciiz(
    s: Union[bytes, bytearray, memoryview], offset: int = 0
) -> StringResult:
    """
    Treats s as null-terminated ASCII string

    :param s: Buffer containing null-terminated ASCII string
    :type s: bytes
    :param offset: Offset in the buffer where the string starts
    :type offset: int
    :return: ASCII string without the null terminator and its decode evidence
    :rtype: :class:`StringResult`

    A missing terminator is reported through ``result.terminated`` /
    ``result.status``.  The historical bytes result is preserved, including
    the old behaviour of returning the remaining buffer when no terminator is
    present.
    """
    raw = _as_bytes(s)
    offset = _check_offset(offset, len(raw))
    terminator = raw.find(b"\x00", offset)
    if terminator >= 0:
        body = raw[offset:terminator]
        consumed = terminator + 1 - offset
        return StringResult(
            body,
            encoding="ascii",
            offset=offset,
            consumed=consumed,
            terminated=True,
            status="ok",
            terminator=b"\x00",
            raw=raw,
            body=body,
            output_encoding="ascii",
        )
    body = raw[offset:]
    return StringResult(
        body,
        encoding="ascii",
        offset=offset,
        consumed=len(body),
        terminated=False,
        status="unterminated",
        raw=raw,
        body=body,
        output_encoding="ascii",
    )


def chunks_iter(s: T, n: int) -> Iterator[T]:
    """Yield successive n-sized chunks from s."""
    if n <= 0:
        raise ValueError("chunk size must be greater than 0")
    return (cast(T, s[i : i + n]) for i in range(0, len(s), n))


def chunks(s: T, n: int) -> List[T]:
    """Return list of successive n-sized chunks from s."""
    return list(chunks_iter(s, n))


def utf16z(
    s: Union[bytes, bytearray, memoryview],
    offset: int = 0,
    encoding: Optional[str] = None,
) -> StringResult:
    """
    Treats s as null-terminated UTF-16 ASCII string

    :param s: Buffer containing null-terminated UTF-16 string
    :type s: bytes
    :param offset: Offset in the buffer where the string starts
    :type offset: int
    :param encoding: Explicit UTF-16 codec (default: use BOM when present,
                     otherwise little-endian UTF-16 as used by Windows)
    :type encoding: str, optional
    :return: ASCII string without '\x00' terminator and its decode evidence
    :rtype: :class:`StringResult`

    Only a terminator aligned at a UTF-16 code-unit boundary is accepted.
    Odd-length input, a missing terminator and undecodable code units are
    reported through ``result.terminated`` / ``result.status`` instead of
    being silently decoded as a shorter string.  The historical fallback
    (returning the remaining input unchanged) is kept for compatibility.
    """
    raw = _as_bytes(s)
    # Be liberal about the optional second positional argument used by
    # callers: it may be either an offset or a codec name.
    if isinstance(offset, str):
        if encoding is not None:
            raise TypeError("encoding specified twice")
        encoding = offset
        offset = 0
    offset = _check_offset(offset, len(raw))

    terminator = None
    idx = raw.find(b"\x00\x00", offset)
    while idx >= 0:
        # Only a code-unit aligned pair terminates a UTF-16 string.  An odd
        # offset here is just one zero byte from each of two adjacent
        # characters and must not make the decoder stop early.
        if (idx - offset) % 2 == 0:
            terminator = idx
            break
        idx = raw.find(b"\x00\x00", idx + 1)

    body_end = terminator if terminator is not None else len(raw)
    body = raw[offset:body_end]

    if encoding is not None:
        codec = encoding
    elif body.startswith(codecs.BOM_UTF16_LE) or body.startswith(
        codecs.BOM_UTF16_BE
    ):
        # Let the "utf-16" codec consume and hide the BOM.
        codec = "utf-16"
    else:
        codec = "utf-16-le"

    if terminator is None:
        status = "truncated" if (len(raw) - offset) % 2 else "unterminated"
        return StringResult(
            raw[offset:],
            encoding=codec,
            offset=offset,
            consumed=len(raw) - offset,
            terminated=False,
            status=status,
            raw=raw,
            body=body,
        )

    try:
        text = body.decode(codec)
    except UnicodeDecodeError as error:
        return StringResult(
            body,
            encoding=codec,
            offset=offset,
            consumed=terminator + 2 - offset,
            terminated=True,
            status="invalid",
            terminator=b"\x00\x00",
            raw=raw,
            body=body,
            error=error,
        )

    # The historical output is an ASCII byte string.  Keep that exact output
    # for the ASCII subset, but don't fail a legal UTF-16 string just because
    # it contains a wider code point: use UTF-8 for those characters.
    try:
        value = text.rstrip("\x00").encode("ascii")
        output_encoding = "ascii"
    except UnicodeEncodeError:
        value = text.rstrip("\x00").encode("utf-8")
        output_encoding = "utf-8"

    return StringResult(
        value,
        encoding=codec,
        offset=offset,
        consumed=terminator + 2 - offset,
        terminated=True,
        status="ok",
        terminator=b"\x00\x00",
        raw=raw,
        body=body,
        output_encoding=output_encoding,
    )


def enhex(s: bytes) -> bytes:
    """
    .. versionchanged:: 2.0.0

        Renamed from :py:meth:`malduck.hex`
    """
    return binascii.hexlify(s)


def unhex(s: Union[str, bytes]) -> bytes:
    return binascii.unhexlify(s)


def uleb128(
    s: Union[bytes, bytearray, memoryview],
    offset: int = 0,
    max_bytes: int = ULEB128_MAX_BYTES,
) -> Optional[ULEB128Result]:
    """
    Unsigned Little-Endian Base 128

    :param s: Buffer containing the ULEB128 value
    :param offset: Offset in the buffer where the value starts
    :param max_bytes: Maximum number of bytes accepted for one value
    :return: ``(absolute_end_offset, value)`` or ``None`` when the encoding is
             truncated, exceeds ``max_bytes`` or is otherwise incomplete

    The returned tuple is a :class:`ULEB128Result` carrying the same read
    range as additional attributes.  Unterminated continuation bytes never
    produce a partial value, and ``max_bytes`` keeps a malicious dump from
    forcing an unbounded big-integer allocation.
    """
    raw = _as_bytes(s)
    offset = _check_offset(offset, len(raw))
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be an integer")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than 0")

    ret = 0
    stop = min(len(raw), offset + max_bytes)
    for idx in range(offset, stop):
        ret |= (raw[idx] & 0x7F) << ((idx - offset) * 7)
        if raw[idx] < 0x80:
            break
    else:
        return None
    return ULEB128Result(idx + 1, ret, offset=offset, raw=raw)


class Base64:
    """Base64 encoder/decoder"""

    def encode(self, s: bytes) -> bytes:
        return b64encode(s)

    def decode(self, s: Union[str, bytes]) -> bytes:
        return b64decode(s)

    __call__ = decode


class Padding:
    """
    Padding PKCS7/NULL
    """

    def __init__(self, style: str) -> None:
        self.style = style

    @staticmethod
    def null(s: bytes, block_size: int) -> bytes:
        return Padding("null").pad(s, block_size)

    def pad(self, s: bytes, block_size: int) -> bytes:
        if not isinstance(block_size, int) or isinstance(block_size, bool):
            raise TypeError("block_size must be an integer")
        if block_size <= 0:
            raise ValueError("block_size must be greater than 0")
        s = _as_bytes(s)
        length = block_size - len(s) % block_size
        if length == block_size:
            padding = b""
        elif self.style == "pkcs7":
            if length > 0xFF:
                raise ValueError("PKCS7 padding length can't exceed 255")
            padding = bytes([length]) * length
        elif self.style == "null":
            padding = b"\x00" * length
        else:
            raise ValueError(f"Unknown padding {self.style}")
        return s + padding

    __call__ = pkcs7 = pad


class Unpadding:
    """
    Unpadding PKCS7/NULL
    """

    def __init__(self, style: str) -> None:
        self.style = style

    def unpad(
        self, s: bytes, block_size: Optional[int] = None
    ) -> StringResult:
        """
        Removes PKCS7/NULL padding.

        Empty input and invalid padding are returned unchanged, matching the
        historical API.  ``block_size`` is optional; when provided, the
        padded buffer length and the reported padding byte must both be valid
        for that block size.  This prevents a malicious last byte from
        stripping an arbitrary amount of data.
        """
        raw = _as_bytes(s)
        if block_size is not None:
            if not isinstance(block_size, int) or isinstance(block_size, bool):
                raise TypeError("block_size must be an integer")
            if block_size <= 0:
                raise ValueError("block_size must be greater than 0")

        if not raw:
            return StringResult(
                raw,
                encoding=None,
                offset=0,
                consumed=0,
                terminated=False,
                status="empty",
                raw=raw,
                body=raw,
                valid_padding=False,
                padding_count=0,
            )

        count = raw[-1]
        valid = False
        if self.style == "pkcs7" and count > 0 and count <= len(raw):
            if block_size is not None:
                valid = (
                    len(raw) % block_size == 0
                    and count <= block_size
                    and raw[-count:] == bytes([count]) * count
                )
            else:
                valid = raw[-count:] == bytes([count]) * count

        value = raw[:-count] if valid else raw
        return StringResult(
            value,
            encoding=None,
            offset=0,
            consumed=len(raw),
            terminated=False,
            status="ok" if valid else "no-padding",
            raw=raw,
            body=raw,
            valid_padding=valid,
            padding_count=count if valid else 0,
            padding_style=self.style,
            block_size=block_size,
        )

    __call__ = pkcs7 = unpad


base64 = Base64()
pad = Padding("pkcs7")
pkcs7 = Padding("pkcs7")
unpad = Unpadding("pkcs7")
unpkcs7 = Unpadding("pkcs7")


# Compatibility aliases for descriptive names used by callers that want to
# make the evidence-carrying return type explicit.
DecodedString = StringResult
StringDecodeResult = StringResult
