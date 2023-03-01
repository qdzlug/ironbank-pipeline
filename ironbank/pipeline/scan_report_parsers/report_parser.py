from abc import ABC
from dataclasses import dataclass
from pathlib import Path
import csv


@dataclass(frozen=True)
class AbstractFinding(ABC):
    # this class can hold similar attributes between different vuln
    # will be used for typing until we can start tying similarities between vulns
    identifier: str
    severity: str
    description: str
    scan_source: str = ""
    package: str = ""
    package_path: str = ""

    def as_dict(self) -> dict:
        return self.__dict__

    def get_dict_from_fieldnames(self, fieldnames: list[str]) -> dict:
        return {k: v for k, v in self.as_dict().items() if k in fieldnames}

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
