import logging
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

Config = Dict[str, Any]
ConfigSet = Dict[str, Config]


class ConflictType(str, Enum):
    """Classification of a field merge conflict."""

    NEW = "new"
    SAME = "same"
    LIST = "list"
    VALUE = "scalar"
    #: Alias making the nature of an unmergeable scalar conflict explicit
    SCALAR = "scalar"
    FAMILY = "family"
    OVERRIDE = "override"


#: Alias for :class:`ConflictType` (some callers use this longer name)
ConfigConflictType = ConflictType

#: Reserved field name used by :class:`ConfigLineage` to describe the family
FAMILY_FIELD = "family"


def is_config_better(base_config: Config, new_config: Config) -> bool:
    """
    Checks whether new config looks more reliable than base.

    .. deprecated::
        This heuristic is no longer used by :class:`ExtractManager`.
        Configs coming from different dumps are merged field by field and
        every decision is recorded in :class:`ConfigLineage`.  In
        particular, a config is *not* considered better just because it has
        more non-empty fields - such conflict must stay observable.

    Kept only for backwards compatibility.
    """
    base = [(k, v) for k, v in base_config.items() if v]
    new = [(k, v) for k, v in new_config.items() if v]
    # Never describe a conflicting config as "better" just because it has
    # more non-empty fields.  Conflict handling belongs to the lineage-aware
    # merge path.
    for key, value in base_config.items():
        if key not in new_config or new_config[key] == value:
            continue
        if isinstance(value, list) and isinstance(new_config[key], list):
            # List extension is still a normal, non-conflicting merge.
            if all(item in new_config[key] for item in value):
                continue
        return False
    return len(new) > len(base)


def encode_for_json(data: Any) -> Any:
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, list) or isinstance(data, tuple):
        return [encode_for_json(item) for item in data]
    elif isinstance(data, dict):
        return {key: encode_for_json(value) for key, value in data.items()}
    else:
        return data


def sanitize_config(config: Config) -> Config:
    """
    Sanitize static configuration by removing empty strings/collections

    :param config: Configuration to sanitize
    :return: Sanitized configuration
    """
    return {k: v for k, v in config.items() if v in [0, False] or v}


def _is_empty_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, list, tuple, dict, set)) and len(value) == 0:
        return True
    return False


def apply_config_part(
    base_config: Config,
    new_config_part: Config,
    *,
    lineage: Optional["ConfigLineage"] = None,
    source: Optional[str] = None,
    family: Optional[str] = None,
    extractor: Optional[str] = None,
    conflict_policy: str = "raise",
) -> Config:
    """
    Apply new part of static configuration. Used internally.

    This function contains the historical merge semantics: missing fields
    are completed, equal values are ignored, lists are joined with
    de-duplication and scalar conflicts raise.

    When ``lineage`` is provided, field versions are recorded as well.

    :param base_config: Base configuration
    :param new_config_part: Changes to apply
    :return: Merged configuration
    """
    if lineage is not None:
        return merge_config_part(
            base_config,
            new_config_part,
            lineage=lineage,
            family=family,
            source=source,
            extractor=extractor,
            conflict_policy=conflict_policy,
        )
    config = dict(base_config)
    for k, v in new_config_part.items():
        if k not in config:
            config[k] = v
        elif config[k] == v:
            continue
        elif _is_empty_value(config[k]) and not _is_empty_value(v):
            config[k] = v
        elif _is_empty_value(v):
            continue
        elif isinstance(config[k], list):
            for el in v:
                if el not in config[k]:
                    config[k] = config[k] + [el]
        else:
            raise RuntimeError(
                f"Extractor tries to override '{config[k]}' "
                f"value of '{k}' with '{v}'"
            )
    return config


class _AttributeDict(dict):
    """Small dict subclass exposing its keys as attributes."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)

    def to_dict(self) -> Dict[str, Any]:
        return _plain_data(self)


def _plain_data(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            key: _plain_data(item)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_plain_data(item) for item in value]
    return value


class FieldVersion(_AttributeDict):
    """
    A single observed version of a configuration field.

    The object is a regular ``dict`` (so it can be serialized and compared
    easily) with attribute access added for convenience.  It contains:

    * ``field`` - field name
    * ``value`` - value observed in this version
    * ``family`` - family which originally provided the value
    * ``effective_family`` - family under which the value is currently kept
    * ``source`` - source file (if known)
    * ``extractor`` - extractor class which provided the value (if known)
    * ``version`` - consecutive version number for this field in a lineage
    * ``order`` - global observation order
    * ``status`` - ``new``, ``same``, ``merged``, ``scalar``, ``conflict``,
      ``replaced``, ``superseded`` or ``override``
    * ``accepted`` - whether this version is the current value
    """

    def __init__(
        self,
        field: str,
        value: Any,
        family: Optional[str] = None,
        source: Optional[str] = None,
        extractor: Optional[str] = None,
        version: int = 1,
        order: int = 0,
        status: str = "new",
        accepted: bool = True,
        effective_family: Optional[str] = None,
        original_version: Optional[int] = None,
        **extra: Any,
    ) -> None:
        super().__init__(
            field=field,
            field_name=field,
            value=value,
            family=family,
            origin_family=family,
            effective_family=(
                effective_family if effective_family is not None else family
            ),
            source=source,
            source_file=source,
            extractor=extractor,
            version=version,
            order=order,
            status=status,
            accepted=accepted,
        )
        if original_version is not None:
            self["original_version"] = original_version
        self.update(extra)


class ConfigConflict(_AttributeDict):
    """
    Description of a field conflict which was encountered while merging
    configs.  Conflicting values are never selected solely by the number of
    non-empty fields; the resolution is explicit and kept in the lineage.
    """

    def __init__(
        self,
        field: str,
        existing: FieldVersion,
        incoming: FieldVersion,
        conflict_type: Any = ConflictType.VALUE,
        resolution: str = "keep_existing",
        **extra: Any,
    ) -> None:
        super().__init__(
            field=field,
            type=conflict_type,
            conflict_type=conflict_type,
            existing=existing,
            incoming=incoming,
            existing_value=existing.value,
            incoming_value=incoming.value,
            existing_source=existing.source,
            incoming_source=incoming.source,
            existing_family=existing.family,
            incoming_family=incoming.family,
            families=[existing.family, incoming.family],
            sources=[existing.source, incoming.source],
            resolution=resolution,
            decision=resolution,
            existing_version=existing.version,
            incoming_version=incoming.version,
        )
        self.update(extra)


class ConfigConflictError(RuntimeError):
    """Raised when a conflict is configured to be fatal."""

    def __init__(
        self,
        message: str,
        conflict: Optional[ConfigConflict] = None,
        lineage: Optional["ConfigLineage"] = None,
    ) -> None:
        super().__init__(message)
        self.conflict = conflict
        self.lineage = lineage


class ConfigLineage(_AttributeDict):
    """
    Complete provenance of one extracted configuration.

    The lineage keeps every observed field version (including values which
    lost a conflict), the source file and the family which provided it.
    ``fields`` contains only current values, while ``versions`` contains the
    full history.  All config merges (within a single dump and between
    dumps) and all override decisions update the same lineage object.
    """

    def __init__(
        self,
        family: Optional[str] = None,
        config: Optional[Config] = None,
        source: Optional[str] = None,
    ) -> None:
        if family is None and config is not None:
            family = config.get(FAMILY_FIELD)
        super().__init__(
            family=family,
            fields={},
            versions={},
            conflicts=[],
            sources=[],
            events=[],
            aliases=[],
            overridden_families=[],
            overridden_lineages={},
            version=0,
        )
        self._order = 0
        self._field_versions: Dict[str, int] = {}
        # Aliases kept as separate dict keys so callers using either name
        # get the same live object.
        self["field_versions"] = self["versions"]
        self["source_files"] = self["sources"]
        self["history"] = self["events"]
        self["overrides"] = self["overridden_families"]
        if config:
            for field, value in config.items():
                self.add_field(field, value, family=family, source=source)

    # ------------------------------------------------------------------
    # Basic helpers
    # ------------------------------------------------------------------
    @property
    def source_files(self) -> List[Optional[str]]:
        return self["sources"]

    @property
    def source(self) -> Optional[str]:
        return self["sources"][0] if self["sources"] else None

    def __getitem__(self, key: str) -> Any:
        # Dynamic convenience views.  They are not stored as regular keys
        # because their contents must always reflect the current lineage.
        if key in ("config", "values"):
            return self.config
        if key == "revision":
            return self["version"]
        if key == "source":
            return self.source
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        if key in ("config", "values", "revision", "source"):
            return True
        return super().__contains__(key)

    @property
    def sources(self) -> List[Optional[str]]:
        return self["sources"]

    @property
    def field_versions(self) -> Dict[str, List[FieldVersion]]:
        return self["versions"]

    @property
    def versions(self) -> Dict[str, List[FieldVersion]]:
        return self["versions"]

    @property
    def fields(self) -> Dict[str, FieldVersion]:
        return self["fields"]

    @property
    def current_fields(self) -> Dict[str, FieldVersion]:
        return self["fields"]

    @property
    def events(self) -> List[Dict[str, Any]]:
        return self["events"]

    @property
    def aliases(self) -> List[str]:
        return self["aliases"]

    @property
    def overridden_families(self) -> List[str]:
        return self["overridden_families"]

    @property
    def overrides(self) -> List[str]:
        """Families overridden by this lineage."""
        return self["overridden_families"]

    @property
    def overridden_lineage_map(self) -> Dict[str, "ConfigLineage"]:
        """Lineages of families hidden by an override decision."""
        return self["overridden_lineages"]

    @property
    def history(self) -> List[Dict[str, Any]]:
        """Alias for the event history."""
        return self["events"]

    @property
    def revision(self) -> int:
        """Number of recorded merge/override events."""
        return self["version"]

    @property
    def config(self) -> Config:
        """Current plain configuration represented by this lineage."""
        return {field: version.value for field, version in self["fields"].items()}

    @property
    def data(self) -> Config:
        """Alias for :py:attr:`config`."""
        return self.config

    @property
    def conflicts(self) -> List[ConfigConflict]:  # type: ignore[override]
        return self["conflicts"]

    @property
    def family(self) -> Optional[str]:  # type: ignore[override]
        return self["family"]

    def _next_order(self) -> int:
        order = self._order
        self._order += 1
        return order

    def _add_source(self, source: Optional[str]) -> None:
        if source is not None and source not in self["sources"]:
            self["sources"].append(source)

    def _next_version(self, field: str) -> int:
        version = self._field_versions.get(field, 0) + 1
        self._field_versions[field] = version
        return version

    def add_event(self, event_type: str, **data: Any) -> Dict[str, Any]:
        """Record a merge/override decision."""
        self["version"] += 1
        event = {
            "type": event_type,
            "order": self._next_order(),
            "family": self["family"],
        }
        event.update(data)
        self["events"].append(event)
        return event

    def add_field(
        self,
        field: str,
        value: Any,
        *,
        family: Optional[str] = None,
        source: Optional[str] = None,
        extractor: Optional[str] = None,
        status: str = "new",
        accepted: bool = True,
        effective_family: Optional[str] = None,
        original_version: Optional[int] = None,
        **extra: Any,
    ) -> FieldVersion:
        """Add one observed field version and return it."""
        if family is None:
            family = self["family"]
        if effective_family is None:
            effective_family = self["family"] or family
        self._add_source(source)
        version = FieldVersion(
            field=field,
            value=value,
            family=family,
            source=source,
            extractor=extractor,
            version=self._next_version(field),
            order=self._next_order(),
            status=status,
            accepted=accepted,
            effective_family=effective_family,
            original_version=original_version,
            **extra,
        )
        self["versions"].setdefault(field, []).append(version)
        if accepted:
            old = self["fields"].get(field)
            if old is not None and old is not version:
                old["accepted"] = False
                if old["status"] not in ("conflict", "superseded"):
                    old["status"] = "superseded"
            self["fields"][field] = version
        return version

    def add_alias(self, family: Optional[str]) -> None:
        if not family:
            return
        aliases = self["aliases"]
        if family != self["family"] and family not in aliases:
            aliases.append(family)

    def add_overridden_family(self, family: str) -> None:
        if family and family not in self["overridden_families"]:
            self["overridden_families"].append(family)

    def add_conflict(self, conflict: ConfigConflict) -> None:
        self["conflicts"].append(conflict)

    def to_dict(self) -> Dict[str, Any]:
        data = _plain_data(self)
        data["config"] = _plain_data(self.config)
        data["values"] = _plain_data(self.config)
        return data

    def as_dict(self) -> Dict[str, Any]:
        """Alias for :py:meth:`to_dict`."""
        return self.to_dict()

    def get_field(self, field: str) -> Optional[FieldVersion]:
        """Current version of ``field`` (or None)."""
        return self["fields"].get(field)

    def get_versions(self, field: str) -> List[FieldVersion]:
        """All observed versions of ``field``."""
        return list(self["versions"].get(field, []))

    def merge(self, incoming: "ConfigLineage", **kwargs: Any) -> bool:
        """Merge another lineage into this one."""
        return merge_lineage(self, incoming, **kwargs)


def make_lineage(
    config: Config,
    *,
    family: Optional[str] = None,
    source: Optional[str] = None,
    extractor: Optional[str] = None,
) -> ConfigLineage:
    """Create lineage for a standalone (previously unseen) config."""
    if family is None:
        family = config.get(FAMILY_FIELD)
    lineage = ConfigLineage(family)
    for field, value in config.items():
        lineage.add_field(
            field,
            value,
            family=family,
            source=source,
            extractor=extractor,
            status="new",
            accepted=True,
        )
    if config:
        lineage.add_event(
            "collect",
            source=source,
            extractor=extractor,
            fields=list(config.keys()),
        )
    return lineage


def merge_lineage(
    target: ConfigLineage,
    incoming: ConfigLineage,
    *,
    winner_family: Optional[str] = None,
    source: Optional[str] = None,
    extractor: Optional[str] = None,
    conflict_policy: str = "keep_existing",
    reason: str = "merge",
    **event_data: Any,
) -> bool:
    """
    Merge ``incoming`` lineage into ``target`` while preserving provenance.

    ``target`` is treated as the preferred/winning side for scalar
    conflicts (unless ``conflict_policy`` is explicitly set to
    ``replace``).  A conflict is always recorded in ``target.conflicts``; it
    is never resolved by comparing the number of non-empty fields.

    :return: True if the resulting config has changed.
    """
    if conflict_policy not in ("keep_existing", "keep", "replace", "raise"):
        raise ValueError(f"Unknown conflict policy: {conflict_policy}")

    target._add_source(source)
    for incoming_source in incoming["sources"]:
        target._add_source(incoming_source)

    previous_config = target.config
    target.add_alias(incoming["family"])
    for alias in incoming["aliases"]:
        target.add_alias(alias)
    for overridden in incoming["overridden_families"]:
        target.add_overridden_family(overridden)

    incoming_field_families = {
        field: version["family"] for field, version in incoming["fields"].items()
    }

    for field, versions in incoming["versions"].items():
        if field == FAMILY_FIELD:
            # Family changes are governed by override relations, never by
            # value comparison.  Keep observations in history, but resolve
            # the effective family explicitly through ``winner_family``.
            family_versions = []
            for version in versions:
                family_versions.append(
                    target.add_field(
                        FAMILY_FIELD,
                        version["value"],
                        family=version["family"],
                        source=version["source"],
                        extractor=version["extractor"],
                        status=version["status"],
                        accepted=False,
                        effective_family=winner_family or target["family"],
                        original_version=version["version"],
                    )
                )
            if winner_family is not None:
                family_version = target["fields"].get(FAMILY_FIELD)
                if family_version is None:
                    # Reuse the incoming observation instead of creating a
                    # duplicate version when it already describes the winner.
                    candidate = family_versions[-1] if family_versions else None
                    if candidate is not None and candidate["value"] == winner_family:
                        candidate["accepted"] = True
                        candidate["effective_family"] = winner_family
                        target["fields"][FAMILY_FIELD] = candidate
                    else:
                        target.add_field(
                            FAMILY_FIELD,
                            winner_family,
                            family=winner_family,
                            source=source,
                            status="override"
                            if incoming["family"] != winner_family
                            else "new",
                            accepted=True,
                            effective_family=winner_family,
                        )
                elif family_version["value"] != winner_family:
                    target.add_field(
                        FAMILY_FIELD,
                        winner_family,
                        family=winner_family,
                        source=source,
                        status="override",
                        accepted=True,
                        effective_family=winner_family,
                    )
                else:
                    family_version["effective_family"] = winner_family
                    family_version["accepted"] = True
            continue
        current_incoming = incoming["fields"].get(field)
        current_target = target["fields"].get(field)
        source_family = incoming_field_families.get(field, incoming["family"])

        if current_target is None:
            # New field - keep all its observed versions.  The last accepted
            # version becomes the current value.
            for version in versions:
                target.add_field(
                    field,
                    version["value"],
                    family=version["family"],
                    source=version["source"],
                    extractor=version["extractor"],
                    status=version["status"],
                    accepted=version["accepted"],
                    effective_family=winner_family or target["family"],
                    original_version=version["version"],
                )
            if current_incoming is not None and field not in target["fields"]:
                target.add_field(
                    field,
                    current_incoming["value"],
                    family=current_incoming["family"],
                    source=current_incoming["source"],
                    extractor=current_incoming["extractor"],
                    status="new",
                    accepted=True,
                    effective_family=winner_family or target["family"],
                    original_version=current_incoming["version"],
                )
            continue

        # Existing field - the target value wins unless it is equal or both
        # sides can be safely combined.
        target_value = current_target["value"]
        incoming_value = current_incoming["value"]
        if target_value == incoming_value:
            target.add_field(
                field,
                incoming_value,
                family=source_family,
                source=current_incoming["source"],
                extractor=current_incoming["extractor"],
                status="same",
                accepted=False,
                effective_family=winner_family or target["family"],
                original_version=current_incoming["version"],
            )
            continue

        if isinstance(target_value, list) and isinstance(incoming_value, list):
            merged = list(target_value)
            for item in incoming_value:
                if item not in merged:
                    merged.append(item)
            if merged == target_value:
                target.add_field(
                    field,
                    incoming_value,
                    family=source_family,
                    source=current_incoming["source"],
                    extractor=current_incoming["extractor"],
                    status="same",
                    accepted=False,
                    effective_family=winner_family or target["family"],
                    original_version=current_incoming["version"],
                )
            else:
                target.add_field(
                    field,
                    merged,
                    family=source_family,
                    source=current_incoming["source"],
                    extractor=current_incoming["extractor"],
                    status="merged",
                    accepted=True,
                    effective_family=winner_family or target["family"],
                    original_version=current_incoming["version"],
                )
            continue

        if _is_empty_value(target_value) and not _is_empty_value(incoming_value):
            # Completion of a previously empty field is not a conflict.
            target.add_field(
                field,
                incoming_value,
                family=source_family,
                source=current_incoming["source"],
                extractor=current_incoming["extractor"],
                status="completed",
                accepted=True,
                effective_family=winner_family or target["family"],
                original_version=current_incoming["version"],
            )
            continue

        if _is_empty_value(incoming_value):
            target.add_field(
                field,
                incoming_value,
                family=source_family,
                source=current_incoming["source"],
                extractor=current_incoming["extractor"],
                status="ignored",
                accepted=False,
                effective_family=winner_family or target["family"],
                original_version=current_incoming["version"],
            )
            continue

        # Unmergeable scalar conflict.
        incoming_version = target.add_field(
            field,
            incoming_value,
            family=source_family,
            source=current_incoming["source"],
            extractor=current_incoming["extractor"],
            status="conflict",
            accepted=False,
            effective_family=winner_family or target["family"],
            original_version=current_incoming["version"],
        )
        replace = conflict_policy == "replace"
        if replace:
            incoming_version["status"] = "replaced"
            incoming_version["accepted"] = True
            target["fields"][field] = incoming_version
            current_target["accepted"] = False
            current_target["status"] = "superseded"
        resolution = "replace_with_incoming" if replace else "keep_existing"
        conflict = ConfigConflict(
            field=field,
            existing=current_target,
            incoming=incoming_version,
            conflict_type=ConflictType.VALUE,
            resolution=resolution,
        )
        target.add_conflict(conflict)
        target.add_event(
            "conflict",
            field=field,
            existing_value=current_target["value"],
            incoming_value=incoming_value,
            existing_family=current_target["family"],
            incoming_family=source_family,
            existing_source=current_target["source"],
            incoming_source=current_incoming["source"],
            resolution=resolution,
            conflict=conflict,
        )
        log.warning(
            "Config field '%s' conflict between %s (%s) and %s (%s); %s",
            field,
            current_target["value"],
            current_target["source"] or current_target["family"],
            incoming_value,
            current_incoming["source"] or source_family,
            resolution,
        )
        if conflict_policy == "raise":
            target.add_event(
                "conflict_error",
                field=field,
                existing_value=current_target["value"],
                incoming_value=incoming_value,
            )
            raise ConfigConflictError(
                f"Extractor tries to override '{current_target['value']}' "
                f"value of '{field}' with '{incoming_value}'",
                conflict=conflict,
                lineage=target,
            )

    if winner_family:
        target["family"] = winner_family
        for version in target["fields"].values():
            if version["family"] is None:
                version["family"] = winner_family
            if version["effective_family"] is None:
                version["effective_family"] = winner_family
        for field_versions in target["versions"].values():
            for version in field_versions:
                if version["family"] is None:
                    version["family"] = winner_family
                if version["effective_family"] is None:
                    version["effective_family"] = winner_family
        if FAMILY_FIELD in target["fields"]:
            target["fields"][FAMILY_FIELD]["effective_family"] = winner_family

    changed = target.config != previous_config
    target.add_event(
        reason,
        source=source,
        extractor=extractor,
        incoming_family=incoming["family"],
        winner_family=winner_family,
        changed=changed,
        **event_data,
    )
    return changed


def merge_config_part(
    base_config: Config,
    new_config_part: Config,
    *,
    lineage: Optional[ConfigLineage] = None,
    family: Optional[str] = None,
    source: Optional[str] = None,
    extractor: Optional[str] = None,
    conflict_policy: str = "raise",
) -> Config:
    """
    Merge a single partial config using :func:`apply_config_part` semantics
    and record all field versions in ``lineage`` (when provided).
    """
    if lineage is None:
        return apply_config_part(base_config, new_config_part)

    current_family = family or base_config.get(FAMILY_FIELD) or lineage["family"]
    incoming_family = new_config_part.get(FAMILY_FIELD, current_family)
    incoming = make_lineage(
        new_config_part,
        family=incoming_family,
        source=source,
        extractor=extractor,
    )
    merge_lineage(
        lineage,
        incoming,
        winner_family=current_family,
        source=source,
        extractor=extractor,
        conflict_policy=conflict_policy,
        reason="merge_part",
    )
    return lineage.config


__all__ = [
    "Config",
    "ConfigConflict",
    "ConfigConflictError",
    "ConfigConflictType",
    "ConfigLineage",
    "ConfigSet",
    "ConflictType",
    "FAMILY_FIELD",
    "FieldVersion",
    "apply_config_part",
    "encode_for_json",
    "is_config_better",
    "make_lineage",
    "merge_config_part",
    "merge_lineage",
    "sanitize_config",
]
