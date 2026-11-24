# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io
from io import BytesIO
from itertools import takewhile
from typing import Optional, cast

from Cryptodome.PublicKey import RSA as RSA_

from ..string.bin import bigint, uint32
from .winhdr import BLOBHEADER, BaseBlob

__all__ = ["PublicKeyBlob", "PrivateKeyBlob", "RSA", "rsa"]


class PublicKeyBlob(BaseBlob):
    magic = b"RSA1"

    def __init__(self) -> None:
        BaseBlob.__init__(self)
        self.e: Optional[int] = None
        self.n: Optional[int] = None

    @staticmethod
    def _read_bigint(buf: BytesIO, size: int) -> Optional[int]:
        """
        Reads exactly ``size`` bytes from the BLOB and interprets them as a
        little-endian bigint. Returns None when the BLOB is truncated.
        """
        raw = buf.read(size)
        if len(raw) != size:
            return None
        return bigint.unpack(raw)

    def parse(self, buf: BytesIO) -> Optional[int]:
        header = buf.read(12)
        if len(header) != 12 or header[:4] != self.magic:
            return None

        self.bitsize = cast(int, uint32(header[4:8], fixed=False))
        self.e = cast(int, uint32(header[8:12], fixed=False))

        # The component sizes below are derived from the header bitsize.
        # It has to be a positive multiple of 16 bits, otherwise neither
        # bitsize / 8 nor bitsize / 16 describes a valid RSA BLOB layout.
        if self.bitsize <= 0 or self.bitsize % 16:
            return None

        n = self._read_bigint(buf, self.bitsize // 8)
        if n is None:
            return None

        self.n = n
        return 12 + self.bitsize // 8

    def export_key(self) -> bytes:
        if not (self.e and self.n):
            raise ValueError("The imported key is invalid")
        return RSA.export_key(self.n, self.e)


class PrivateKeyBlob(PublicKeyBlob):
    magic = b"RSA2"

    def __init__(self) -> None:
        PublicKeyBlob.__init__(self)
        self.p1: Optional[int] = None
        self.p2: Optional[int] = None
        self.exp1: Optional[int] = None
        self.exp2: Optional[int] = None
        self.coeff: Optional[int] = None
        self.d: Optional[int] = None

    def parse(self, buf: BytesIO) -> Optional[int]:
        off = PublicKeyBlob.parse(self, buf)
        if off is None:
            return None

        half = self.bitsize // 16
        # Every private component must be present in full: a truncated RSA2
        # BLOB must never be silently exported as a half-parsed public key.
        for name, size in (
            ("p1", half),
            ("p2", half),
            ("exp1", half),
            ("exp2", half),
            ("coeff", half),
            ("d", self.bitsize // 8),
        ):
            component = self._read_bigint(buf, size)
            if component is None:
                return None
            setattr(self, name, component)

        return off + 5 * half + self.bitsize // 8

    def export_key(self) -> bytes:
        # The header, bitsize, modulus and every private component have to
        # describe one and the same key before a PEM may be produced.
        components = (
            self.e,
            self.n,
            self.d,
            self.p1,
            self.p2,
            self.coeff,
        )
        if not all(components):
            raise ValueError("The imported key is invalid")
        return RSA.export_key(
            self.n,
            self.e,
            self.d,
            self.p1,
            self.p2,
            self.coeff,
            consistency_check=True,
        )


BlobTypes = {
    6: PublicKeyBlob,
    7: PrivateKeyBlob,
}


class RSA:
    algorithms = (0x0000A400,)  # RSA

    @staticmethod
    def import_key(data: bytes) -> Optional[bytes]:
        r"""
        Extracts key from buffer containing :class:`PublicKeyBlob` or :class:`PrivateKeyBlob` data

        :param data: Buffer with `BLOB` structure data
        :type data: bytes
        :return: RSA key in PEM format
        :rtype: bytes
        """
        try:
            return RSA_.import_key(data).export_key()
        except (ValueError, IndexError, TypeError):
            pass

        if len(data) < BLOBHEADER.sizeof():
            return None

        buf = io.BytesIO(data)
        header = BLOBHEADER.parse(buf.read(BLOBHEADER.sizeof()))
        if header.bType not in BlobTypes:
            return None

        if header.aiKeyAlg not in RSA.algorithms:
            return None

        obj = BlobTypes[header.bType]()
        # Refuse truncated / malformed BLOBs instead of exporting whatever
        # fraction of the key material happened to parse.
        if obj.parse(buf) is None:
            return None

        try:
            return obj.export_key()
        except (ValueError, IndexError, TypeError):
            return None

    @staticmethod
    def export_key(
        n: int,
        e: int,
        d: Optional[int] = None,
        p: Optional[int] = None,
        q: Optional[int] = None,
        crt: Optional[int] = None,
        consistency_check: bool = False,
    ) -> bytes:
        r"""
        Constructs key from tuple of RSA components

        :param n: RSA modulus n
        :param e: Public exponent e
        :param d: Private exponent d
        :param p: First factor of n
        :param q: Second factor of n
        :param crt: CRT coefficient q
        :param consistency_check: Verify that the components describe a single
            mathematically consistent RSA key (used for parsed RSA2 BLOBs)
        :return: RSA key in PEM format
        :rtype: bytes
        """

        def wrap(x):
            return None if x is None else int(x)

        tup = wrap(n), wrap(e), wrap(d), wrap(p), wrap(q), wrap(crt)
        # PyCryptodome accepts only variable-length tuples
        tup_w = tuple(takewhile(lambda x: x is not None, tup))
        return RSA_.construct(  # type: ignore
            tup_w, consistency_check=consistency_check
        ).export_key()


rsa = RSA
