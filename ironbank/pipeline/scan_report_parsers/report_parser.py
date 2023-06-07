import csv
from abc import ABC
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class AbstractFinding(ABC):
    # this class can hold similar attributes between different vuln
    # will be used for typing until we can start tying similarities between vulns
    identifier: str
    severity: str
    description: str = ""
    scan_source: str = ""
    package: str | None = ""
    package_path: str | None = ""

    @property
    def finding(self) -> str:
        """Read only alias for identifier."""
        return self.identifier

    @property
    def packagePath(self) -> str | None:  # pylint: disable=invalid-name
        """Read only alias for package_path."""
        return self.package_path

    @property
    def scanSource(self) -> str:  # pylint: disable=invalid-name
        """Read only alias for scan_source."""
        return self.scan_source

    def as_dict(self) -> dict[str, Any]:
        """Return dictionary representation of object including attributes and
        properties."""
        return {
            **self.__dict__,
            "finding": self.finding,
            "packagePath": self.packagePath,
            "scanSource": self.scanSource,
        }

    def get_dict_from_fieldnames(self, fieldnames: list[str]) -> dict[str, Any]:
        """Return dictionary of all attributes matching input fieldnames Sort
        order for keys in dictionary match order of fieldnames."""
        # using OrderedDict so the keys are ordered in the same way the fieldnames are ordered
        finding_dict = OrderedDict({k: None for k in fieldnames})
        for key, value in self.as_dict().items():
            if key in fieldnames:
                finding_dict[key] = value
        return dict(finding_dict)

    def get_justification(self, justifications: dict) -> str:
        id_ = (
            self.identifier,
            self.package,
            self.package_path if self.package_path != "pkgdb" else None,
        )
        return justifications.get(id_, "") if justifications else ""


@dataclass
class ReportParser(ABC):
    """Base class for scan report parsing Provides generic helper methods for
    writing out results, deduping findings, etc."""

    @classmethod
    def dedupe_findings_by_attr(
        cls, findings: list[AbstractFinding], attribute: str
    ) -> list[AbstractFinding]:
        """Remove duplicate findings from list by finding attribute."""
        unique_findings = {}
        for finding in findings:
            if not (attr_val := getattr(finding, attribute)) in unique_findings:
                unique_findings[attr_val] = finding
        return [v for v in unique_findings.values()]

    @classmethod
    def write_csv_from_dict_list(
        cls, csv_dir: Path, dict_list: list[dict], fieldnames: list, filename: str
    ) -> None:
        """Create csv file based off prepared data.

        The data must be provided as a list of dictionaries.
        """
        filepath = Path(csv_dir, filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open(mode="w", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            if dict_list:
                writer.writerows(dict_list)
