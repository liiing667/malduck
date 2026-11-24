"""
Tests for the carving budget and the YARA match remap generation.

A dump containing many fake MZ/ELF signatures, overlapping images or a
damaged trailing section must not force an unbounded number of full binary
loads, and the matches collected on the parent dump have to be explicitly
remapped into each carved binary's address space instead of reusing raw
physical offsets against a differently laid-out object.
"""
from unittest import mock

from malduck.extractor.extract_manager import MAX_CARVED_BINARIES, ExtractManager
from malduck.procmem.binmem import ProcessMemoryBinary
from malduck.procmem.region import Region
from malduck.yara import YaraRulesetMatch


class FakeMemory:
    """Minimal ProcessMemory stand-in with explicit region translation."""

    def __init__(self, name, regions, magic_hits=None):
        self.name = name
        self.regions = regions
        self.magic_hits = magic_hits or []

    def findv(self, magic):
        return iter(list(self.magic_hits))

    def _region_for_va(self, va):
        return next(
            (r for r in self.regions if r.addr <= va < r.addr + r.size), None
        )

    def _region_for_offset(self, offset):
        return next(
            (r for r in self.regions if r.offset <= offset < r.offset + r.size),
            None,
        )

    def v2p(self, addr, length=None):
        region = self._region_for_va(addr)
        return None if region is None else region.v2p(addr)

    def p2v(self, offset, length=None):
        region = self._region_for_offset(offset)
        return None if region is None else region.p2v(offset)

    def __repr__(self):
        return f"<FakeMemory {self.name}>"


class FakeBinary(ProcessMemoryBinary):
    """ProcessMemoryBinary subclass counting full-load attempts."""

    __magic__ = b"MZ"
    load_count = 0
    image_regions = None

    def __init__(self, base, regions, valid=True):
        self.imgbase = base
        self.regions = regions
        self.is_image = False
        self._image = None
        self._valid = valid
        FakeBinary.load_count += 1

    def is_valid(self):
        return self._valid

    def _reload_as_image(self):
        raise NotImplementedError()

    def is_image_loaded_as_memdump(self):
        return False

    @property
    def image(self):
        if self.image_regions is None:
            return None
        image = FakeBinary(self.imgbase, self.image_regions)
        image.image_regions = None
        return image

    @classmethod
    def from_memory(cls, memory, base=None, **kwargs):
        return cls(base, memory.regions)


class EmptyCarver:
    """Binary class that simply never yields anything."""

    __name__ = "EmptyCarver"
    __magic__ = b"\x7fELF"

    @staticmethod
    def load_binaries_from_memory(procmem, limit=None):
        return iter(())


def make_manager():
    manager = ExtractManager.__new__(ExtractManager)
    manager.binary_classes = [FakeBinary, EmptyCarver]
    return manager


def make_match(rule="rule", identifier="string", offset=0, data=b"X"):
    class _Instance:
        def __init__(self, offset, matched_data):
            self.offset = offset
            self.matched_data = matched_data

    class _String:
        def __init__(self):
            self.identifier = "$" + identifier
            self.instances = [_Instance(offset, data)]

    class _Rule:
        def __init__(self):
            self.rule = rule
            self.strings = [_String()]
            self.namespace = "ns"
            self.tags = ()
            self.meta = {}

    return YaraRulesetMatch([_Rule()])


def test_carve_budget_caps_full_loads():
    """Only MAX_CARVED_BINARIES candidates are fully loaded from a noisy dump."""
    FakeBinary.load_count = 0
    dump = FakeMemory(
        "dump",
        [Region(0x10000, 0x10000, 0, 0, 0, 0)],
        magic_hits=[0x10000 + 0x100 * i for i in range(50)],
    )

    carved = list(make_manager().carve_procmem(dump))

    assert len(carved) == MAX_CARVED_BINARIES
    # Remaining fake MZ signatures must never reach from_memory / is_valid.
    assert FakeBinary.load_count == MAX_CARVED_BINARIES


def test_legitimate_multi_image_within_budget_is_kept():
    """A handful of legitimate images (dmp + image mappings) all get through."""
    FakeBinary.load_count = 0
    FakeBinary.image_regions = [Region(0x10000, 0x1000, 0, 0, 0, 0)]
    try:
        # 3 genuine MZ headers, each producing a dump and an image mapping.
        dump = FakeMemory(
            "dump",
            [Region(0x10000, 0x10000, 0, 0, 0, 0)],
            magic_hits=[0x10000, 0x14000, 0x18000],
        )
        carved = list(make_manager().carve_procmem(dump))
        # 3 dumps + 3 images, well below MAX_CARVED_BINARIES.
        assert len(carved) == 6
        assert FakeBinary.load_count == 6
    finally:
        FakeBinary.image_regions = None


def test_budget_is_shared_across_binary_classes():
    """PE candidates consume the budget before ELF carving even starts."""
    FakeBinary.load_count = 0
    manager = make_manager()

    class Elfed(EmptyCarver):
        entered = False

        @staticmethod
        def load_binaries_from_memory(procmem, limit=None):
            Elfed.entered = True
            # Must receive the already-consumed remainder of the budget.
            assert limit == MAX_CARVED_BINARIES - 2
            return iter(())

    manager.binary_classes = [FakeBinary, Elfed]
    dump = FakeMemory(
        "dump",
        [Region(0x10000, 0x10000, 0, 0, 0, 0)],
        magic_hits=[0x10000, 0x11000],
    )

    carved = list(manager.carve_procmem(dump))
    assert len(carved) == 2
    assert Elfed.entered


def test_source_level_limit_and_legacy_default():
    FakeBinary.load_count = 0
    dump = FakeMemory(
        "dump",
        [Region(0x10000, 0x10000, 0, 0, 0, 0)],
        magic_hits=[0x10000 + i for i in range(20)],
    )

    # Only the dump mapping is produced (image is None), so one yielded
    # binary per magic hit and the limit stops at 3.
    limited = list(FakeBinary.load_binaries_from_memory(dump, limit=3))
    assert len(limited) == 3
    assert FakeBinary.load_count == 3

    FakeBinary.load_count = 0
    # limit=None preserves the previous unbounded behaviour.
    assert len(list(FakeBinary.load_binaries_from_memory(dump))) == 20
    assert FakeBinary.load_count == 20


def test_limit_counts_image_mappings_too():
    """Both dump and image mappings share the same carving budget."""
    FakeBinary.load_count = 0
    FakeBinary.image_regions = [Region(0x10000, 0x1000, 0, 0, 0, 0)]
    try:
        dump = FakeMemory(
            "dump",
            [Region(0x10000, 0x10000, 0, 0, 0, 0)],
            magic_hits=[0x10000 + i for i in range(20)],
        )
        limited = list(FakeBinary.load_binaries_from_memory(dump, limit=4))
        # 2 mappings per magic hit, budget 4 -> 2 magic hits consumed.
        assert len(limited) == 4
        # 2 dump objects + 2 image objects fully constructed.
        assert FakeBinary.load_count == 4
    finally:
        FakeBinary.image_regions = None


def test_remap_across_different_region_layouts():
    """Raw dump offsets must not be reused against a rebuilt image layout."""
    # PE geometry: ImageBase 0x140000000, section RVA 0x1000 / raw 0x200.
    dump = FakeMemory("dump", [Region(0x140000000, 0x3000, 0, 0, 0, 0)])
    image = FakeMemory(
        "image",
        [
            Region(0x140000000, 0x200, 0, 0, 0, 0),
            Region(0x140001000, 0x1000, 0, 0, 0, 0x200),
        ],
    )

    # A valid section hit: dump phys 0x1500 -> VA 0x140001500 in both views.
    remapped = ExtractManager._remap_matches(
        make_match(offset=0x1500), dump, image
    )
    assert remapped["rule"]["string"][0].offset == 0x140001500
    # The old direct-offset mapping lost this hit entirely.
    assert image.p2v(0x1500) is None

    # Dump header padding has no representation in the image and must be
    # dropped instead of being ghost-mapped onto the section.
    dropped = ExtractManager._remap_matches(
        make_match(rule="other", offset=0x300), dump, image
    )
    assert "other" not in dropped
    assert image.p2v(0x300) == 0x140001100


def test_remap_identity_path():
    """When source is the destination, remapping is plain p2v."""
    mem = FakeMemory("mem", [Region(0x400000, 0x1000, 0, 0, 0, 0)])
    remapped = ExtractManager._remap_matches(make_match(offset=0x20), mem, mem)
    assert remapped["rule"]["string"][0].offset == 0x400020


def test_push_procmem_uses_one_match_generation():
    """Parent dump and every carved binary share the collected matches."""
    dump = FakeMemory(
        "dump",
        [Region(0x10000, 0x2000, 0, 0, 0, 0)],
        magic_hits=[0x10000, 0x11000],
    )
    matches = make_match(offset=0x10)
    manager = make_manager()
    manager.match_procmem = lambda procmem: matches
    manager.carve_procmem = lambda procmem: [
        FakeBinary(0x10000, dump.regions),
        FakeBinary(0x11000, dump.regions),
    ]

    calls = []

    def fake_extract(self, procmem, procmem_matches, match_source):
        calls.append((procmem, match_source))
        assert procmem_matches is matches
        return None

    with mock.patch.object(ExtractManager, "_extract_procmem", fake_extract):
        manager.push_procmem(dump, rip_binaries=True)

    # Parent + two carved binaries, all anchored to the dump as match source.
    assert len(calls) == 3
    assert all(source is dump for _, source in calls)
