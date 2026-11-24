import struct

import pytest

from malduck import procmempe
from malduck.procmem import Region


def _mutate_calc_section(field: int, index: int, value: int) -> bytes:
    data = bytearray(open("tests/files/calc.exe", "rb").read())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_header_offset = pe_offset + 24
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_offset = optional_header_offset + optional_header_size + index * 40
    struct.pack_into("<I", data, section_offset + field, value)
    return bytes(data)


def _make_pe64() -> bytes:
    """Minimal PE+ with .text and an empty .bss section."""
    file_alignment, section_alignment = 0x200, 0x1000
    pe_offset, optional_size, headers_size = 0x80, 0xF0, 0x200
    header = bytearray(headers_size)
    struct.pack_into("<H", header, 0, 0x5A4D)
    struct.pack_into("<I", header, 0x3C, pe_offset)
    struct.pack_into(
        "<4sHHIIIHH",
        header,
        pe_offset,
        b"PE\x00\x00",
        0x8664,
        2,
        0,
        0,
        0,
        optional_size,
        0x22,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<I", header, optional + 16, 0x1000)
    struct.pack_into("<Q", header, optional + 24, 0x140000000)
    struct.pack_into("<II", header, optional + 32, section_alignment, file_alignment)
    struct.pack_into("<I", header, optional + 56, 0x3000)
    struct.pack_into("<I", header, optional + 60, headers_size)
    struct.pack_into("<I", header, optional + 108, 16)
    section_table = optional + optional_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        header,
        section_table,
        b".text\x00\x00\x00",
        0x1A0,
        0x1000,
        0x200,
        headers_size,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        header,
        section_table + 40,
        b".bss\x00\x00\x00\x00",
        0x300,
        0x2000,
        0,
        0,
        0,
        0,
        0,
        0,
        0xC0000080,
    )
    return bytes(header) + b"\x90" * 0x200


def test_pe_layout_identity_roundtrip():
    for name in ("calc.exe", "96emptysections.exe", "96workingsections.exe"):
        original = open(f"tests/files/{name}", "rb").read()
        with procmempe(original, image=True) as p:
            assert p.store() == original

    pe64 = _make_pe64()
    with procmempe(pe64, image=True) as p:
        assert p.store() == pe64
        assert p.pe.is64bit
        assert p.pe.sections[1].SizeOfRawData == 0


@pytest.mark.parametrize(
    "field,index,value",
    [
        (16, 0, 0x10000000),  # raw size beyond EOF
        (20, 0, 0),  # first section starts at file offset zero
        (20, 1, 0x100),  # section raw data inside headers
        (12, 0, 0x100),  # section starts inside headers
        (12, 2, 0x500),  # unsorted virtual addresses
        (16, 0, 0x54000),  # section overlaps the next one
    ],
)
def test_pe_layout_rejects_inconsistent_file(field, index, value):
    with pytest.raises(ValueError):
        procmempe(_mutate_calc_section(field, index, value), image=True)


def test_store_fails_closed_on_unmapped_section():
    calc = open("tests/files/calc.exe", "rb").read()
    truncated = calc[:0x53400]
    regions = [Region(0x1000000, 0x53400, 0, 0, 0, 0)]
    with procmempe(truncated, base=0x1000000, regions=regions) as p:
        with pytest.raises(ValueError):
            p.store()


def test_contradictory_plain_load_is_lazy():
    # Plain (non-image) construction must stay cheap and not raise: the
    # contradiction is only rejected when the layout is actually used.
    procmempe(_mutate_calc_section(20, 0, 0))
