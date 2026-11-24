import pytest

from malduck import MAX_ADDRESS, MemoryRangeError, procmem
from malduck.procmem import Region


def make_regions():
    #  aaaaabbbbb ccccc
    #  10000 10005 10010
    payload = b"aaaaabbbbbccccc"
    regions = [
        Region(0x10000, 5, 0, 0, 0, 0),
        Region(0x10005, 5, 0, 0, 0, 5),
        Region(0x10010, 5, 0, 0, 0, 10),
    ]
    return procmem(payload, regions=regions)


def test_valid_multi_region_reads_are_unchanged():
    mem = make_regions()

    # Adjacent regions are still merged into one contiguous read.
    assert mem.readv(0x10000, 10) == b"aaaaabbbbb"
    assert mem.readv(0x10002, 6) == b"aaabbb"
    assert mem.readv(0x10000) == b"aaaaabbbbb"

    # A gap still terminates a contiguous read instead of inventing zeroes.
    assert mem.readv(0x10000, 0x20) == b"aaaaabbbbb"
    assert list(mem.readv_regions(0x10000, 0x20, contiguous=False)) == [
        (0x10000, b"aaaaabbbbb"),
        (0x10010, b"ccccc"),
    ]

    # Zero-length reads stay empty and don't require a valid mapping.
    assert mem.readv(0x10000, 0) == b""
    assert mem.readv(0xDEADBEEF, 0) == b""


def test_zero_length_patch_is_a_noop():
    mem = make_regions()
    before = mem.readp(0)

    assert mem.patchv(0xDEADBEEF, b"") is None
    assert mem.readp(0) == before


def test_negative_and_overflowing_ranges_fail_before_mapping():
    mem = make_regions()

    with pytest.raises(MemoryRangeError):
        mem.readv(0x10000, -1)
    with pytest.raises(MemoryRangeError):
        mem.readv(-1, 1)
    with pytest.raises(MemoryRangeError):
        mem.readv(MAX_ADDRESS - 1, 2)
    with pytest.raises(MemoryRangeError):
        mem.readv(MAX_ADDRESS, 1)
    with pytest.raises(MemoryRangeError):
        list(mem.iter_regions(addr=MAX_ADDRESS - 1, length=2))
    with pytest.raises(MemoryRangeError):
        list(mem.iter_regions(offset=-1))
    with pytest.raises(MemoryRangeError):
        mem.v2p(MAX_ADDRESS - 1, 2)
    with pytest.raises(MemoryRangeError):
        mem.p2v(MAX_ADDRESS - 1, 2)


def test_region_metadata_range_validation():
    with pytest.raises(MemoryRangeError):
        Region(-1, 1, 0, 0, 0, 0)
    with pytest.raises(MemoryRangeError):
        Region(0, -1, 0, 0, 0, 0)
    with pytest.raises(MemoryRangeError):
        Region(0, 1, 0, 0, 0, -1)
    with pytest.raises(MemoryRangeError):
        Region(MAX_ADDRESS - 1, 2, 0, 0, 0, 0)
    with pytest.raises(MemoryRangeError):
        Region(0, 2, 0, 0, 0, MAX_ADDRESS - 1)

    # trim_range uses the same range rules as the public query methods.
    region = Region(0x1000, 0x10, 0, 0, 0, 0)
    with pytest.raises(MemoryRangeError):
        region.trim_range(0x1000, -1)
    with pytest.raises(MemoryRangeError):
        region.trim_range(MAX_ADDRESS - 1, 2)
    assert region.trim_range(0x1000, 0) is None


def test_overlapping_regions_are_rejected_consistently():
    # 0x1008-0x1018 overlaps 0x1000-0x1010.  Address translation, reads and
    # writes must all reject the same ambiguous mapping.
    mem = procmem(
        b"A" * 0x20,
        regions=[
            Region(0x1000, 0x10, 0, 0, 0, 0),
            Region(0x1008, 0x10, 0, 0, 0, 0x10),
        ],
    )

    with pytest.raises(MemoryRangeError):
        list(mem.iter_regions())
    with pytest.raises(MemoryRangeError):
        mem.readv(0x1000, 4)
    with pytest.raises(MemoryRangeError):
        mem.v2p(0x1000)
    with pytest.raises(MemoryRangeError):
        mem.addr_region(0x1000)
    with pytest.raises(MemoryRangeError):
        mem.patchv(0x1000, b"x")


def test_regions_are_ordered_by_the_queried_dimension():
    # Region metadata in a dump doesn't have to be sorted.  Address queries
    # must still find the right virtual mapping, while offset queries use
    # physical order (offset 0 is the second region here).
    mem = procmem(
        b"AAAABBBB",
        regions=[
            Region(0x2000, 4, 0, 0, 0, 4),
            Region(0x1000, 4, 0, 0, 0, 0),
        ],
    )

    assert mem.readv(0x1000, 4) == b"AAAA"
    assert mem.readv(0x2000, 4) == b"BBBB"
    assert mem.v2p(0x1000) == 0
    assert mem.v2p(0x2000) == 4
    assert mem.p2v(0) == 0x1000
    assert mem.p2v(4) == 0x2000
    assert [region.addr for region in mem.iter_regions()] == [0x1000, 0x2000]
    assert [region.addr for region in mem.iter_regions(offset=0)] == [
        0x1000,
        0x2000,
    ]
    assert list(mem.iter_regions(offset=0))[0].addr == 0x1000


def test_short_physical_mapping_is_observable():
    # The region claims eight bytes but the dump only contains four.  Reading
    # the valid prefix is fine; reading beyond it must not silently return a
    # short buffer that callers could mistake for a complete block.
    mem = procmem(b"0123", regions=[Region(0x1000, 8, 0, 0, 0, 0)])

    assert mem.readv(0x1000, 4) == b"0123"
    with pytest.raises(MemoryRangeError):
        mem.readv(0x1000, 8)
    with pytest.raises(MemoryRangeError):
        list(mem.readv_regions(0x1000))

    # v2p advertises a usable offset only when the requested length is fully
    # backed by the memory buffer.
    assert mem.v2p(0x1000, 4) == 0
    assert mem.v2p(0x1000, 8) is None

    # patchv validates the complete range before writing a single byte.
    before = mem.readp(0)
    with pytest.raises(MemoryRangeError):
        mem.patchv(0x1000, b"abcdefgh")
    assert mem.readp(0) == before


def test_patchv_requires_one_complete_region():
    mem = procmem(
        b"aaaa" + b"bbbb",
        regions=[
            Region(0x1000, 4, 0, 0, 0, 0),
            Region(0x1004, 4, 0, 0, 0, 4),
            Region(0x2000, 4, 0, 0, 0, 8),
        ],
    )

    mem.patchv(0x1000, b"AAAA")
    assert mem.readv(0x1000, 4) == b"AAAA"
    assert mem.readv(0x1004, 4) == b"bbbb"

    # Patching across the boundary between two adjacent regions is rejected
    # before any part of the buffer is modified.
    before = mem.readp(0)
    with pytest.raises(ValueError):
        mem.patchv(0x1003, b"xy")
    assert mem.readp(0) == before

    # Too long for a single region, in a gap, or at an unmapped address.
    with pytest.raises(ValueError):
        mem.patchv(0x1000, b"12345")
    with pytest.raises(ValueError):
        mem.patchv(0x1FFF, b"x")
    with pytest.raises(ValueError):
        mem.patchv(0x2004, b"x")


def test_v2p_p2v_and_reads_agree_on_range_boundaries():
    mem = make_regions()

    assert mem.v2p(0x10000, 10) == 0
    assert mem.v2p(0x10004, 6) == 4
    assert mem.v2p(0x1000F, 2) is None  # crosses the gap
    assert mem.p2v(0, 10) == 0x10000
    assert mem.p2v(4, 6) == 0x10004

    # A read starting in a gap keeps the legacy short/empty result.
    assert mem.readv(0x1000F, 2) == b""


def test_repeated_operations_do_not_leak_state():
    mem = make_regions()

    # A short cross-gap read or a failed write must leave the region map
    # usable for the next call.
    assert mem.readv(0x10000, 0x20) == b"aaaaabbbbb"
    with pytest.raises(ValueError):
        mem.patchv(0x1000F, b"x")

    assert mem.readv(0x10000, 5) == b"aaaaa"
    mem.patchv(0x10000, b"ZZ")
    assert mem.readv(0x10000, 5) == b"ZZaaa"
