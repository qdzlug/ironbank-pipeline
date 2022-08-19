from dataclasses import dataclass
from pathlib import Path
import csv


@dataclass
class AbstractVuln:
    # this class can hold similar attributes between different vuln
    # will be used for typing until we can start tying similarities between vulns
    pass


@dataclass
class ReportParser:
    @classmethod
    def get_justification(self, vuln: AbstractVuln, justifications: dict):
        id = (
            (vuln.cve, vuln.package, vuln.package_path)
            if vuln.package_path != "pkgdb"
            else None
        )
        return justifications[id] if () in justifications else None

    @classmethod
    def write_csv_from_dict_list(csv_dir, dict_list, fieldnames, filename):
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
