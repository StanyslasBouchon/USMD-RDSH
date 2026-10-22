"""In-memory catalogue of mutation (service) definitions for one USD."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ncp.protocol.commands.send_mutation_properties import MutationSummary
from .service import Service
from .yaml_parser import ServiceYamlParser


@dataclass
class _CatalogEntry:
    service: Service
    source_yaml: Optional[str] = None


class MutationCatalog:
    """Stores parsed :class:`Service` objects and optional source YAML for NCP sync."""

    def __init__(self) -> None:
        self._entries: dict[str, _CatalogEntry] = {}

    def register(self, service: Service, source_yaml: Optional[str] = None) -> None:
        """Insert or replace a service definition."""
        self._entries[service.name] = _CatalogEntry(service=service, source_yaml=source_yaml)

    def get(self, name: str) -> Optional[Service]:
        """Return the service named *name*, or None."""
        ent = self._entries.get(name)
        return ent.service if ent else None

    def get_yaml(self, name: str) -> Optional[str]:
        """Return stored source YAML for *name*, or None."""
        ent = self._entries.get(name)
        return ent.source_yaml if ent else None

    def all_services(self) -> list[Service]:
        """All registered services (arbitrary order)."""
        return [e.service for e in self._entries.values()]

    def count(self) -> int:
        """Number of services in the catalogue."""
        return len(self._entries)

    def snapshot_mutations(self) -> list[dict]:
        """Serialisable mutation rows for status snapshots (includes YAML when stored)."""
        rows: list[dict] = []
        for name, ent in self._entries.items():
            svc = ent.service
            rows.append(
                {
                    "name": name,
                    "type": svc.service_type.value,
                    "version": svc.version,
                    "deps": svc.dependencies,
                    "yaml": ent.source_yaml,
                }
            )
        return rows

    def summaries_for_broadcast(self) -> list[MutationSummary]:
        """Build NCP payloads: include YAML when we have it locally."""
        out: list[MutationSummary] = []
        for name, ent in self._entries.items():
            out.append(
                MutationSummary(
                    name=name,
                    version=ent.service.version,
                    definition_yaml=ent.source_yaml,
                )
            )
        return out

    def apply_remote_summaries(self, summaries: list[MutationSummary]) -> None:
        """Merge remote summaries: full YAML replaces; version-only bumps metadata."""
        for s in summaries:
            if s.definition_yaml:
                parsed = ServiceYamlParser.parse(s.name, s.definition_yaml)
                if parsed.is_ok():
                    svc = parsed.unwrap()
                    svc.version = s.version
                    self.register(svc, s.definition_yaml)
            else:
                ent = self._entries.get(s.name)
                if ent is not None and s.version > ent.service.version:
                    ent.service.version = s.version
