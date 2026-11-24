import pytest

from malduck.extractor import (
    ConfigConflictError,
    ConfigLineage,
    ExtractManager,
)
from malduck.extractor.extract_manager import ExtractionContext


class FakeModules:
    """Minimal modules object required by ExtractManager.push_config."""

    override_paths = {
        "citadel": [["citadel", "zeus"]],
        "zeus": [["citadel", "zeus"]],
    }

    @staticmethod
    def compare_family_overrides(first, second):
        if first == "citadel" and second == "zeus":
            return -1
        if first == "zeus" and second == "citadel":
            return 1
        return 0


def test_same_family_dumps_are_completed_and_keep_lineage():
    manager = ExtractManager(FakeModules())

    assert manager.push_config(
        {"family": "evil", "urls": ["http://a"], "key": "old"}, source="dump-1"
    )
    assert manager.push_config(
        {"family": "evil", "urls": ["http://b", "http://a"], "botnet": "b"},
        source="dump-2",
    )

    assert manager.config == [
        {
            "family": "evil",
            "urls": ["http://a", "http://b"],
            "key": "old",
            "botnet": "b",
        }
    ]

    lineage = manager.get_lineage("evil")
    assert isinstance(lineage, ConfigLineage)
    assert lineage.sources == ["dump-1", "dump-2"]
    # Every field version retains the file it came from.
    assert [v.source for v in lineage.field_versions["urls"]] == ["dump-1", "dump-2"]
    assert lineage.fields["key"].source == "dump-1"
    assert lineage.fields["botnet"].source == "dump-2"
    # Final config and the lineage share the very same object.
    assert manager.configs["evil"].lineage is lineage


def test_scalar_conflict_is_not_resolved_by_field_count():
    manager = ExtractManager(FakeModules())

    manager.push_config({"family": "evil", "key": "first"}, source="dump-1")
    # This config has many more non-empty fields, but the conflicting value
    # must not silently replace the first one just because of its size.
    manager.push_config(
        {"family": "evil", "key": "second", "a": 1, "b": 2, "c": 3},
        source="dump-2",
    )

    assert manager.config[0]["key"] == "first"
    # Non-conflicting fields are still completed.
    assert manager.config[0]["a"] == 1
    assert manager.config[0]["b"] == 2
    assert manager.config[0]["c"] == 3

    conflict = manager.conflicts[0]
    assert conflict.field == "key"
    assert conflict.existing_value == "first"
    assert conflict.incoming_value == "second"
    assert conflict.resolution == "keep_existing"
    # Both versions, and both source files, stay visible.
    versions = manager.get_lineage("evil").field_versions["key"]
    assert [(v.value, v.source, v.accepted) for v in versions] == [
        ("first", "dump-1", True),
        ("second", "dump-2", False),
    ]


def test_conflict_policy_can_be_fatal():
    manager = ExtractManager(FakeModules())
    manager.conflict_policy = "raise"
    manager.push_config({"family": "evil", "key": "first"}, source="dump-1")

    with pytest.raises(ConfigConflictError):
        manager.push_config({"family": "evil", "key": "second"}, source="dump-2")

    # Conflict is recorded before the error is propagated.
    assert manager.get_lineage("evil").conflicts[0].field == "key"


def test_override_does_not_discard_stored_family_lineage():
    manager = ExtractManager(FakeModules())

    manager.push_config(
        {"family": "zeus", "zeus_only": True, "urls": ["http://z"]},
        source="zeus-dump",
    )
    manager.push_config(
        {"family": "citadel", "citadel_only": True, "urls": ["http://c"]},
        source="citadel-dump",
    )

    # Override still hides the lower-priority family from the final config
    # and preserves the legacy winner-only config shape.
    assert [config["family"] for config in manager.config] == ["citadel"]
    assert "zeus" not in manager.configs
    assert manager.config[0]["citadel_only"] is True
    assert manager.config[0]["urls"] == ["http://c"]
    assert "zeus_only" not in manager.config[0]

    # ...but the stored family, its source file, fields and versions are
    # retained instead of being deleted.
    citadel = manager.get_lineage("citadel")
    zeus = manager.get_lineage("zeus")
    assert zeus is not None
    assert "zeus" in manager.overridden_configs
    assert manager.overridden_configs["zeus"]["zeus_only"] is True
    assert manager.overridden_families == ["zeus"]
    assert citadel.overridden_families == ["zeus"]
    assert citadel.aliases == ["zeus"]
    assert zeus["winner"] == "citadel"
    assert citadel.sources == ["citadel-dump", "zeus-dump"]
    assert zeus.sources == ["zeus-dump"]
    assert zeus.fields["zeus_only"].source == "zeus-dump"
    assert any(
        event["type"] == "override_decision" and event["winner"] == "citadel"
        for event in citadel.events
    )


def test_legacy_config_shape_and_field_order_are_preserved():
    manager = ExtractManager(FakeModules())

    manager.push_config(
        {"family": "evil", "first": 1, "urls": ["a"]}, source="dump-1"
    )
    manager.push_config(
        {"family": "evil", "second": 2, "urls": ["b"]}, source="dump-2"
    )

    config = manager.config[0]
    assert isinstance(config, dict)
    # Inherited dict shape: no provenance bookkeeping leaks into the config.
    assert set(config) == {"family", "first", "urls", "second"}
    # Existing fields keep their order; completion appends new keys.
    assert list(config) == ["family", "first", "urls", "second"]


def test_single_dump_lineage_is_shared_by_partial_merges():
    manager = ExtractManager(FakeModules())
    context = ExtractionContext(manager, source="single.dmp")

    class FakeExtractor:
        pass

    FakeExtractor.__name__ = "FakeExtractor"

    context.push_config({"first": 1, "urls": ["a"]}, FakeExtractor())
    context.push_config({"family": "evil", "second": 2}, FakeExtractor())

    assert context.collected_config["family"] == "evil"
    assert context.collected_config["first"] == 1
    assert context.lineage.config == context.collected_config
    assert context.lineage.sources == ["single.dmp"]
    assert context.lineage.fields["first"].source == "single.dmp"
    assert context.lineage.fields["first"].family == "evil"


def test_override_decision_keeps_incoming_lineage_when_stored_family_wins():
    manager = ExtractManager(FakeModules())

    manager.push_config(
        {"family": "citadel", "citadel_only": True, "urls": ["http://c"]},
        source="citadel-dump",
    )
    manager.push_config(
        {"family": "zeus", "zeus_only": True, "urls": ["http://z"]},
        source="zeus-dump",
    )

    # Stored (stronger) family remains the only visible config.
    assert manager.config == [
        {"family": "citadel", "citadel_only": True, "urls": ["http://c"]}
    ]
    # Incoming family is neither dropped from history nor from its own data.
    assert manager.overridden_configs["zeus"] == {
        "family": "zeus",
        "zeus_only": True,
        "urls": ["http://z"],
    }
    assert manager.get_lineage("zeus").sources == ["zeus-dump"]
    assert manager.get_lineage("citadel").overridden_lineages["zeus"] is (
        manager.get_lineage("zeus")
    )
    assert manager.get_lineage("zeus")["overridden_by"] == "citadel"


def test_fixed_comparison_is_deterministic_and_never_loses_lineage():
    def run_fixed_case():
        manager = ExtractManager(FakeModules())
        manager.push_config(
            {"family": "evil", "key": "first", "urls": ["a"]}, source="dump-1"
        )
        manager.push_config(
            {"family": "evil", "key": "second", "run": "new", "urls": ["b"]},
            source="dump-2",
        )
        return (
            [dict(config) for config in manager.config],
            manager.get_lineage("evil").to_dict(),
        )

    first = run_fixed_case()
    second = run_fixed_case()
    # The same fixed input produces the same final config and the same
    # lineage (including both conflicting versions and both sources).
    assert first == second
    assert first[0] == [
        {
            "family": "evil",
            "key": "first",
            "urls": ["a", "b"],
            "run": "new",
        }
    ]
    assert first[1]["sources"] == ["dump-1", "dump-2"]
