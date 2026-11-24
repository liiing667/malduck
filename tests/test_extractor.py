import os

from malduck import procmem, procmempe
from malduck.extractor import ExtractorModules, ExtractManager


def test_scan_base64():
    modules = ExtractorModules("tests/files/modules")
    assert "Unbase64" in [extractor.__name__ for extractor in modules.extractors]

    for fname in os.listdir("tests/files"):
        fpath = os.path.join("tests/files", fname)
        if os.path.isfile(fpath):
            extractor = ExtractManager(modules)
            extractor.push_file(fpath)
            if extractor.config:
                assert len(extractor.config) == 1
                matched_base = extractor.config[0].get("base64", False)
            else:
                matched_base = False
            should_be_base = fname.endswith(".b64")
            # To be or not to be
            assert matched_base == should_be_base


def test_scan_ollydbg():
    modules = ExtractorModules("tests/files/modules")
    olly = procmempe.from_file("tests/files/ollydbg.exe", image=True)
    cfg = olly.extract(modules)[0]

    assert cfg["family"] == "ollydbg"
    assert sorted(cfg["olly"]) == [
        " - OllyDbg is a JIT debugger\n",
        " - OllyDbg is in Explorer's menu\n",
        " - OllyDbg is not in Explorer's menu"
    ]
    assert "olly_is_not" in cfg["matches"]


def test_apliebe():
    modules = ExtractorModules("tests/files/modules")
    p = procmem.from_file("tests/files/mal1.b64")
    assert p.extract(modules) == [{
        "base64": True,
        "family": "apliebe",
        "str_to_int_offs": [0x1000a410]
    }]


def test_weaky():
    modules = ExtractorModules("tests/files/modules")
    weaky = procmem(b"weakyx")
    strongy = procmem(b"strongy")
    strongyweaky = procmem(b"strongyweakyx")
    assert not weaky.extract(modules)
    assert strongy.extract(modules) == [{
        "family": "weaky"
    }]
    assert strongyweaky.extract(modules) == [{
        "family": "weaky",
        "weak": True,
        "weaky": True
    }]


def test_multirules():
    modules = ExtractorModules("tests/files/modules")
    multistring = procmem(b"FiRsT string fIrSt string"
                          b"SeCoNd string sEcOnD string"
                          b"ThIrD string tHiRd string")
    assert multistring.extract(modules) == [{
        'family': 'multistring',
        'first': ['FiRsT string', 'fIrSt string', 'SeCoNd string', 'sEcOnD string'],
        'third': ['ThIrD string']
    }]

    multistring_v2 = procmem(b"ThIrD stringa0a1b2b3c4c5d6d7e8e9FoUrTh string")
    assert multistring_v2.extract(modules) == [{
        'family': 'multistring_v2',
        'matched': ['v2'],
        'third': ['ThIrD string']
    }]


class ErrorCatchingManager(ExtractManager):
    """
    ExtractManager that collects error evidence instead of just logging it
    """

    def __init__(self, modules):
        super().__init__(modules)
        self.errors = []

    def on_extractor_error(self, exc, extractor, method_name):
        self.errors.append((extractor.__class__.__name__, method_name, exc))


def test_error_shortcircuits_final():
    modules = ExtractorModules("tests/files/modules")
    manager = ErrorCatchingManager(modules)
    # Required (strong) extractor method raises in the middle of extraction
    assert manager.push_procmem(procmem(b"errfin_boom")) is None
    # Error evidence is collected and shared within extraction context...
    assert [
        (extractor_name, method_name)
        for extractor_name, method_name, exc in manager.errors
    ] == [("ErrFin", "boom")]
    # ...but final methods are short-circuited, so partial config
    # is not reported as a clean, complete family result
    assert manager.config == []


def test_final_called_without_error():
    modules = ExtractorModules("tests/files/modules")
    manager = ErrorCatchingManager(modules)
    # Independent, legitimate extractor still works (including final methods)
    assert manager.push_procmem(procmem(b"okfin_trigger")) == "okfin"
    assert manager.errors == []
    assert manager.config == [{
        "family": "okfin",
        "final": True
    }]


def test_weak_compatible_with_final():
    modules = ExtractorModules("tests/files/modules")
    # Weak-only match still doesn't produce config on its own
    assert not procmem(b"weakfin_weak").extract(modules)
    # Strong match flushes weak config parts and final methods are called
    assert procmem(b"weakfin_weak weakfin_strong").extract(modules) == [{
        "family": "weakfin",
        "weak": True,
        "final": True
    }]
