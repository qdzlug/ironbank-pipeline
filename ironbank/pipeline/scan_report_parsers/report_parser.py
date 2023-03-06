from abc import ABC
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
import csv


@dataclass
class AbstractFinding(ABC):
    # this class can hold similar attributes between different vuln
    # will be used for typing until we can start tying similarities between vulns
    identifier: str
    severity: str
    description: str = ""
    scan_source: str = ""
    package: str = ""
    package_path: str = ""

    @property
    def packagePath(self):
        return self.package_path

    @property
    def scanSource(self):
        return self.scan_source

    def as_dict(self) -> dict:
        return self.__dict__

    def get_dict_from_fieldnames(self, fieldnames: list[str]) -> dict:
        # using OrderedDict so the keys are ordered in the same way the fieldnames are ordered
        finding_dict = OrderedDict({k: None for k in fieldnames})
        for k, v in self.as_dict().items():
            if k in fieldnames:
                finding_dict[k] = v
        return finding_dict

    def get_justification(self, justifications: dict) -> str:
        id = (
            self.identifier,
            self.package,
            self.package_path if self.package_path != "pkgdb" else None,
        )
        return justifications.get(id, "") if justifications else ""  # type: ignore


# make this an abstract class once all inheriting classes are defined
@dataclass
class ReportParser:
    @classmethod
    def dedupe_findings_by_attr(cls, findings, attribute):
        """
        Remove duplicate findings from list by finding attribute
        """
        unique_findings = {}
        for finding in findings:
            if not (attr_val := getattr(finding, attribute)) in unique_findings:
                unique_findings[attr_val] = finding
        return [v for v in unique_findings.values()]

    @classmethod
    def write_csv_from_dict_list(
        cls, csv_dir: Path, dict_list: list[dict], fieldnames: list, filename: str
    ) -> None:
        """
        Create csv file based off prepared data. The data must be provided as a list
        of dictionaries and the rest will be taken care of.

        """
        filepath = Path(csv_dir, filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open(mode="w", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            if dict_list:
                writer.writerows(dict_list)
