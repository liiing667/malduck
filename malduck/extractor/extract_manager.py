import json
import logging
import warnings
from typing import Any, Dict, Iterator, List, Optional, Type

from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..procmem.binmem import ProcessMemoryBinary
from ..yara import Yara, YaraRuleOffsets, YaraRulesetMatch
from .config_utils import (
    Config,
    ConfigConflict,
    ConfigConflictError,
    ConfigLineage,
    ConflictType,
    encode_for_json,
    make_lineage,
    merge_lineage,
    sanitize_config,
)
from .extractor import Extractor
from .modules import ExtractorModules

log = logging.getLogger(__name__)

__all__ = [
    "ConfigConflict",
    "ConfigConflictError",
    "ConfigLineage",
    "ConflictType",
    "ExtractManager",
    "ExtractionContext",
]


class ExtractManager:
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    """

    def __init__(self, modules: ExtractorModules) -> None:
        self.modules = modules
        self.binary_classes: List[Type[ProcessMemoryBinary]] = [
            ProcessMemoryPE,
            ProcessMemoryELF,
        ]
        self.configs: Dict[str, Config] = {}
        #: Lineage for every family seen so far (including overridden ones)
        self.lineages: Dict[str, ConfigLineage] = {}
        #: Families that lost an override decision, kept for audit purposes
        self.overridden_families: List[str] = []
        #: Full configs hidden by override decisions (never discarded)
        self.overridden_configs: Dict[str, Config] = {}
        #: Policy used for unmergeable scalar conflicts:
        #: "keep_existing" (default), "replace" or "raise".
        self.conflict_policy: str = "keep_existing"

    @property
    def rules(self) -> Yara:
        """
        Bound Yara rules
        :rtype: :class:`malduck.yara.Yara`
        """
        return self.modules.rules

    @property
    def extractors(self) -> List[Type[Extractor]]:
        """
        Bound extractor modules
        :rtype: List[Type[:class:`malduck.extractor.Extractor`]]
        """
        return self.modules.extractors

    def on_error(self, exc: Exception, extractor: Extractor) -> None:
        """
        Handler for all exceptions raised by :py:meth:`Extractor.handle_yara`.

        .. deprecated:: 2.1.0
           Look at :py:meth:`ExtractManager.on_extractor_error` instead.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor object which raised the exception
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        self.on_extractor_error(exc, extractor, "handle_yara")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods (including :py:meth:`Extractor.handle_yara`).

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        import traceback

        log.warning(
            "%s.%s raised an exception: %s",
            extractor.__class__.__name__,
            method_name,
            traceback.format_exc(),
        )

    def push_file(self, filepath: str, base: int = 0) -> Optional[str]:
        """
        Pushes file for extraction. Config extractor entrypoint.

        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :return: Detected family if configuration looks better than already stored one
        """
        log.debug("Started extraction of file %s:%x", filepath, base)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.push_procmem(p, rip_binaries=True, source=filepath)

    def match_procmem(self, p: ProcessMemory) -> YaraRulesetMatch:
        """
        Performs Yara matching on ProcessMemory using modules
        bound with current ExtractManager.
        """
        matches = p.yarap(self.rules, extended=True)
        log.debug("Matched rules: %s", ",".join(list(matches.keys())))
        return matches

    def carve_procmem(self, p: ProcessMemory) -> Iterator[ProcessMemoryBinary]:
        """
        Carves binaries from ProcessMemory to try configuration extraction
        using every possible address mapping.
        """
        for binclass in self.binary_classes:
            carved_bins = binclass.load_binaries_from_memory(p)
            for carved_bin in carved_bins:
                log.debug(
                    f"carve: Found {carved_bin.__class__.__name__} "
                    f"at offset {carved_bin.regions[0].offset}"
                )
                yield carved_bin

    @property
    def lineage(self) -> Dict[str, ConfigLineage]:
        """Lineage of every family seen by this manager (active or overridden)."""
        return self.lineages

    @property
    def config_lineage(self) -> Dict[str, ConfigLineage]:
        """Alias for :py:attr:`lineage`."""
        return self.lineages

    def get_lineage(self, family: str) -> Optional[ConfigLineage]:
        """Return lineage for a family (also for families hidden by override)."""
        return self.lineages.get(family)

    def get_config_lineage(self, family: str) -> Optional[ConfigLineage]:
        """Alias for :py:meth:`get_lineage`."""
        return self.get_lineage(family)

    def get_config(self, family: str) -> Optional[Config]:
        """Return active config or a config hidden by an override."""
        return self.configs.get(family) or self.overridden_configs.get(family)

    def get_sources(self, family: str) -> List[Optional[str]]:
        """Source files which contributed to the family."""
        lineage = self.get_lineage(family)
        return list(lineage["sources"]) if lineage is not None else []

    @property
    def configs_lineage(self) -> Dict[str, ConfigLineage]:
        """Alias for :py:attr:`lineage`."""
        return self.lineages

    @property
    def sources(self) -> Dict[str, List[Optional[str]]]:
        """Source files used by each family, in observation order."""
        return {
            family: lineage["sources"] for family, lineage in self.lineages.items()
        }

    @property
    def field_versions(self) -> Dict[str, Dict[str, Any]]:
        """Per-family field version history."""
        return {
            family: lineage["versions"] for family, lineage in self.lineages.items()
        }

    @property
    def override_decisions(self) -> List[Dict[str, Any]]:
        """All distinct override decisions recorded in all lineages."""
        decisions = []
        seen = set()
        for lineage in self.lineages.values():
            for event in lineage["events"]:
                if event["type"] != "override_decision":
                    continue
                key = (
                    event.get("loser"),
                    event.get("winner"),
                    event.get("source"),
                    event.get("decision"),
                )
                if key in seen:
                    continue
                seen.add(key)
                decisions.append(event)
        decisions.sort(key=lambda event: event.get("order", 0))
        return decisions

    @property
    def conflicts(self) -> List[ConfigConflict]:
        """All conflicts recorded in all lineages, in observation order."""
        result = []
        for lineage in self.lineages.values():
            result.extend(lineage["conflicts"])
        result.sort(key=lambda conflict: conflict["incoming"]["order"])
        return result

    def _get_lineage(self, family: str) -> ConfigLineage:
        lineage = self.lineages.get(family)
        if lineage is None:
            config = self.configs.get(family)
            if config is None:
                lineage = ConfigLineage(family)
            else:
                lineage = getattr(config, "lineage", None) or make_lineage(
                    config, family=family
                )
            self.lineages[family] = lineage
        return lineage

    def _set_config(
        self, family: str, config: Config, lineage: Optional[ConfigLineage] = None
    ) -> Config:
        """Store config while keeping its provenance attached."""
        if lineage is None:
            lineage = make_lineage(config, family=family)
        self.lineages[family] = lineage
        stored = _TrackedConfig(config)
        stored.lineage = lineage
        stored.source = lineage["sources"]
        stored.sources = lineage["sources"]
        stored.source_file = lineage["sources"][0] if lineage["sources"] else None
        stored.field_versions = lineage["versions"]
        stored.conflicts = lineage["conflicts"]
        stored.aliases = lineage["aliases"]
        stored.overridden_families = lineage["overridden_families"]
        stored.overridden_lineages = lineage["overridden_lineages"]
        stored.events = lineage["events"]
        self.configs[family] = stored
        return stored

    def _drop_active_family(self, family: str, winner: Optional[str] = None) -> None:
        """Hide a family from the final config without discarding its data."""
        config = self.configs.pop(family, None)
        if config is not None:
            self.overridden_configs[family] = config
        if family not in self.overridden_families:
            self.overridden_families.append(family)
        lineage = self.lineages.get(family)
        if lineage is not None:
            if winner is not None:
                lineage.add_event("overridden", winner=winner)
                lineage["winner"] = winner
                lineage["overridden_by"] = winner

    def _merge_into_family(
        self,
        family: str,
        incoming: ConfigLineage,
        *,
        source: Optional[str] = None,
        reason: str = "merge",
    ) -> bool:
        lineage = self._get_lineage(family)
        try:
            changed = merge_lineage(
                lineage,
                incoming,
                winner_family=family,
                source=source,
                conflict_policy=self.conflict_policy,
                reason=reason,
            )
        except ConfigConflictError:
            # Keep the collected config synchronized with lineage even when
            # the caller requested a fatal conflict.
            self._set_config(family, lineage.config, lineage)
            raise
        self._set_config(family, lineage.config, lineage)
        return changed

    def push_config(
        self,
        config: Config,
        source: Optional[str] = None,
        source_file: Optional[str] = None,
        lineage: Optional[ConfigLineage] = None,
        extractor: Optional[Any] = None,
        conflict_policy: Optional[str] = None,
        raise_on_conflict: bool = False,
    ) -> bool:
        """
        Push a complete config extracted from one dump.

        Configs coming from different dumps are merged field by field.
        Missing fields are completed, lists are joined with de-duplication
        and every observed value (including a value which lost a conflict)
        stays in :py:attr:`lineage`.  Conflicts are never resolved by
        picking the config with more non-empty fields.

        ``conflict_policy`` can override :py:attr:`conflict_policy` for this
        single call (``keep_existing``, ``replace`` or ``raise``).
        ``raise_on_conflict`` is a shorthand for ``conflict_policy="raise"``.
        """
        if conflict_policy is None and not raise_on_conflict:
            return self._push_config(
                config,
                source=source,
                source_file=source_file,
                lineage=lineage,
                extractor=extractor,
            )

        previous_policy = self.conflict_policy
        self.conflict_policy = (
            conflict_policy or ("raise" if raise_on_conflict else previous_policy)
        )
        try:
            return self._push_config(
                config,
                source=source,
                source_file=source_file,
                lineage=lineage,
                extractor=extractor,
            )
        finally:
            self.conflict_policy = previous_policy

    def _push_config(
        self,
        config: Config,
        source: Optional[str] = None,
        source_file: Optional[str] = None,
        lineage: Optional[ConfigLineage] = None,
        extractor: Optional[Any] = None,
    ) -> bool:
        """
        Push a complete config extracted from one dump.

        Configs coming from different dumps are merged field by field.
        Missing fields are completed, lists are joined with de-duplication
        and every observed value (including a value which lost a conflict)
        stays in :py:attr:`lineage`.  Conflicts are never resolved by
        picking the config with more non-empty fields.
        """
        if not config.get("family"):
            return False

        if source is None:
            source = source_file
        if lineage is None:
            lineage = make_lineage(
                config,
                family=config["family"],
                source=source,
                extractor=getattr(extractor, "__name__", extractor),
            )
        else:
            lineage._add_source(source)

        family = config["family"]
        if family in self.configs:
            log.debug("%s config merge with previous one", family)
            return self._merge_into_family(
                family, lineage, source=source, reason="merge_same_family"
            )

        if family in self.modules.override_paths:
            # 'citadel' > 'zeus'
            # If 'zeus' appears but we have already 'citadel', we should ignore
            # 'zeus'.  Otherwise we should get 'citadel' instead of 'zeus'.
            overridden = []
            overriding = []
            for stored_family in list(self.configs.keys()):
                if stored_family == family:
                    continue
                score = self.modules.compare_family_overrides(family, stored_family)
                if score == -1:
                    overridden.append(stored_family)
                elif score == 1:
                    overriding.append(stored_family)

            if overriding:
                # Stored family wins.  Its config stays untouched (legacy
                # shape), but the incoming lineage is kept separately and
                # linked from the winner's lineage.
                winner = overriding[0]
                log.debug(
                    "%s config doesn't look better than previous one (overridden by %s)",
                    family,
                    winner,
                )
                self.lineages[family] = lineage
                winner_lineage = self._get_lineage(winner)
                winner_lineage.add_alias(family)
                winner_lineage.add_overridden_family(family)
                winner_lineage["winner"] = winner
                winner_lineage["overridden_lineages"][family] = lineage
                for incoming_source in lineage["sources"]:
                    winner_lineage._add_source(incoming_source)
                winner_lineage.add_event(
                    "override_decision",
                    loser=family,
                    winner=winner,
                    source=source,
                    decision="keep_stored",
                )
                lineage.add_event(
                    "override_decision",
                    loser=family,
                    winner=winner,
                    source=source,
                    decision="keep_stored",
                )
                lineage["winner"] = winner
                lineage["overridden_by"] = winner
                self.overridden_configs[family] = _TrackedConfig(
                    lineage.config, lineage=lineage, source=lineage["sources"]
                )
                if family not in self.overridden_families:
                    self.overridden_families.append(family)
                return False

            if overridden:
                # Incoming family wins.  Keep the legacy winner-only config
                # shape, but retain every stored config and its lineage.
                winner_lineage = lineage
                winner_lineage["winner"] = family
                for stored_family in overridden:
                    stored_lineage = self._get_lineage(stored_family)
                    winner_lineage.add_alias(stored_family)
                    winner_lineage.add_overridden_family(stored_family)
                    winner_lineage["overridden_lineages"][stored_family] = (
                        stored_lineage
                    )
                    for stored_source in stored_lineage["sources"]:
                        winner_lineage._add_source(stored_source)
                    winner_lineage.add_event(
                        "override_decision",
                        loser=stored_family,
                        winner=family,
                        source=source,
                        decision="incoming_wins",
                    )
                    stored_lineage.add_event(
                        "overridden",
                        winner=family,
                        source=source,
                    )
                    stored_lineage["winner"] = family
                    stored_lineage["overridden_by"] = family
                    log.debug(
                        "%s config looks better (overrides %s)", family, stored_family
                    )
                    self._drop_active_family(stored_family, winner=family)
                self._set_config(family, config, winner_lineage)
                return True

        log.debug("New %s config collected", family)
        self._set_config(family, config, lineage)
        return True

    def _extract_procmem(
        self,
        p: ProcessMemory,
        matches,
        source: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> Optional[str]:
        log.debug("%s - ripping...", repr(p))
        if source is None:
            source = source_file
        if source is None:
            source = _source_from_procmem(p)
        # Create extraction context for single file
        manager = ExtractionContext(parent=self, source=source)
        # Map offset matches to VA using procmem address mapping
        va_matches = matches.remap(p.p2v)
        # Push ProcessMemory for extraction with mapped Yara matches
        manager.push_procmem(p, _matches=va_matches)
        # Get final configurations
        config = manager.collected_config
        if config.get("family"):
            log.debug("%s - found %s!", repr(p), config.get("family"))
            if self.push_config(config, source=source, lineage=manager.lineage):
                return config["family"]
            else:
                return None
        else:
            log.debug("%s - no luck.", repr(p))
            return None

    def push_procmem(
        self,
        p: ProcessMemory,
        rip_binaries: bool = False,
        source: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> Optional[str]:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param rip_binaries: Look for binaries (PE, ELF) in provided ProcessMemory and try to perform extraction using
            specialized variants (ProcessMemoryPE, ProcessMemoryELF)
        :type rip_binaries: bool (default: False)
        :return: Detected family if configuration looks better than already stored one
        """
        if source is None:
            source = source_file
        if source is None:
            source = _source_from_procmem(p)
        matches = self.match_procmem(p)
        if not matches:
            log.debug("No Yara matches.")
            return None

        binaries = self.carve_procmem(p) if rip_binaries else iter([])

        family = self._extract_procmem(p, matches, source=source)
        for binary in binaries:
            family = self._extract_procmem(binary, matches, source=source) or family
        return family

    @property
    def config(self) -> List[Config]:
        """
        Extracted configuration (list of configs for each extracted family)

        Overridden families are intentionally not returned here (legacy
        behavior), but remain available through :py:attr:`overridden_configs`
        and :py:attr:`lineage`.
        """
        return [config for family, config in self.configs.items()]

    @property
    def all_configs(self) -> List[Config]:
        """Active configs plus configs hidden by override decisions."""
        return [
            *self.configs.values(),
            *self.overridden_configs.values(),
        ]

    @property
    def configs_all(self) -> Dict[str, Config]:
        """Mapping of active and overridden configs."""
        return {**self.configs, **self.overridden_configs}


class _TrackedConfig(dict):
    """Plain dict with lineage attached as an attribute (shape-compatible)."""

    lineage: ConfigLineage
    source: List[Optional[str]]
    sources: List[Optional[str]]
    source_file: Optional[str]
    field_versions: Dict[str, Any]
    conflicts: List[ConfigConflict]
    aliases: List[str]
    overridden_families: List[str]
    overridden_lineages: Dict[str, ConfigLineage]
    events: List[Dict[str, Any]]

    def __init__(
        self,
        config: Optional[Config] = None,
        *,
        lineage: Optional[ConfigLineage] = None,
        source: Optional[List[Optional[str]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(config or {}, **kwargs)
        if lineage is not None:
            self.lineage = lineage
        if source is not None:
            self.source = source
            self.sources = source
            self.source_file = source[0] if source else None
        elif lineage is not None:
            self.source = lineage["sources"]
            self.sources = lineage["sources"]
            self.source_file = lineage["sources"][0] if lineage["sources"] else None
        if lineage is not None:
            self.field_versions = lineage["versions"]
            self.conflicts = lineage["conflicts"]
            self.aliases = lineage["aliases"]
            self.overridden_families = lineage["overridden_families"]
            self.overridden_lineages = lineage["overridden_lineages"]
            self.events = lineage["events"]


def _source_from_procmem(p: ProcessMemory) -> Optional[str]:
    """Best-effort source name for ProcessMemory objects."""
    for attr in ("source", "filename", "filepath", "path"):
        value = getattr(p, attr, None)
        if isinstance(value, str) and value:
            return value
    opened_file = getattr(p, "opened_file", None)
    name = getattr(opened_file, "name", None)
    if isinstance(name, str) and name:
        return name
    return None


class ExtractionContext:
    """
    Single-dump extraction context (single family)
    """

    def __init__(
        self,
        parent: ExtractManager,
        source: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> None:
        #: Collected configuration so far (especially useful for "final" extractors)
        self.collected_config: Config = {}
        self.globals: Dict[str, Any] = {}
        self.parent = parent  #: Bound ExtractManager instance
        #: Source file/dump which produced this partial config
        self.source = source if source is not None else source_file
        self.source_file = self.source
        #: Lineage shared by all partial merges and the final config
        self.lineage = ConfigLineage()
        #: Override decisions made while ripping a single dump
        self.override_decisions: List[Dict[str, Any]] = []

    @property
    def family(self) -> Optional[str]:
        """Matched family"""
        return self.collected_config.get("family")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        self.parent.on_extractor_error(exc, extractor, method_name)

    def push_procmem(
        self, p: ProcessMemory, _matches: Optional[YaraRulesetMatch] = None
    ) -> None:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _matches: YaraRulesetMatch object (used internally)
        :type _matches: :class:`malduck.yara.YaraRulesetMatch`
        """
        matches = _matches or p.yarav(self.parent.rules, extended=True)
        used_matches = set()  # Which yara rules had a matching extractor
        # For each extractor...
        for ext_class in self.parent.extractors:
            extractor = ext_class(self)

            if type(extractor.yara_rules) is str:
                raise TypeError(
                    f'"{extractor.__class__.__name__}.yara_rules" cannot be a string, convert it into a list of strings'
                )

            # For each rule identifier in extractor.yara_rules...
            for rule in extractor.yara_rules:
                if rule in matches:
                    used_matches.add(rule)
                    try:
                        if hasattr(extractor, "handle_yara"):
                            warnings.warn(
                                "Extractor.handle_yara is deprecated, use Extractor.handle_match",
                                DeprecationWarning,
                            )
                            getattr(extractor, "handle_yara")(
                                p, YaraRuleOffsets(matches[rule])
                            )
                        else:
                            extractor.handle_match(p, matches[rule])
                    except Exception as exc:
                        self.parent.on_error(exc, extractor)

        log.info("The following matches were used: %s", list(used_matches))
        if not used_matches:
            log.warning("YARA rules didn't trigger any extractor! Is there a typo?")

    def push_config(self, config: Config, extractor: Extractor) -> None:
        """
        Pushes new partial config

        If strong config provides different family than stored so far
        and that family overrides stored family - set stored family
        Example: citadel overrides zeus

        :param config: Partial config object
        :type config: dict
        :param extractor: Extractor object reference
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        config = encode_for_json(config)
        try:
            json.dumps(config)
        except (TypeError, OverflowError) as e:
            log.debug("Config is not JSON-encodable (%s): %s", str(e), repr(config))
            raise RuntimeError("Config must be JSON-encodable")

        config = sanitize_config(config)

        if not config:
            return

        log.debug(
            "%s found the following config parts: %s",
            extractor.__class__.__name__,
            sorted(config.keys()),
        )

        origin_family = config.get("family")
        winner_family = self.family
        conflict_policy = "raise"
        if origin_family and winner_family and origin_family != winner_family:
            log.debug(
                "%s tells it's %s", extractor.__class__.__name__, origin_family
            )
            overrides = self.parent.modules.compare_family_overrides(
                origin_family, winner_family
            )
            if not overrides:
                raise RuntimeError(
                    f"Ripped both {winner_family} and {origin_family} "
                    f"from the same ProcessMemory which is not expected"
                )
            if overrides == -1:
                # New family overrides the one collected so far.  It becomes
                # effective, but old fields and their sources are retained.
                loser = winner_family
                winner_family = origin_family
                self.collected_config["family"] = origin_family
                conflict_policy = "replace"
                decision = "incoming_wins"
            else:
                # Stored family wins; incoming fields are still completed.
                loser = origin_family
                config["family"] = winner_family
                decision = "keep_stored"
            self.override_decisions.append(
                {
                    "loser": loser,
                    "winner": winner_family,
                    "source": self.source,
                    "decision": decision,
                }
            )
            self.lineage.add_event(
                "override_decision",
                loser=loser,
                winner=winner_family,
                source=self.source,
                decision=decision,
            )
            self.lineage.add_overridden_family(loser)
            self.lineage["winner"] = winner_family
        elif origin_family and not winner_family:
            winner_family = origin_family
        elif origin_family:
            log.debug(
                "%s tells it's %s", extractor.__class__.__name__, origin_family
            )

        incoming = make_lineage(
            config,
            family=origin_family or winner_family,
            source=self.source,
            extractor=extractor.__class__.__name__,
        )
        try:
            merge_lineage(
                self.lineage,
                incoming,
                winner_family=winner_family,
                source=self.source,
                extractor=extractor.__class__.__name__,
                conflict_policy=conflict_policy,
                reason="merge_part",
            )
        finally:
            # Lineage and collected config must never diverge, including
            # when a conflict policy aborts the merge.
            self.collected_config = self.lineage.config

    @property
    def config(self) -> Config:
        """
        Returns collected config, but if family is not matched - returns empty dict.
        Family is not included in config itself, look at :py:attr:`ProcmemExtractManager.family`.
        """
        if self.family is None:
            return {}
        return self.collected_config
