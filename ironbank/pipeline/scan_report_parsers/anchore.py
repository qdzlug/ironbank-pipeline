# maybe security and gate parsers should be separate

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from ironbank.pipeline.scan_report_parsers.report_parser import (
    AbstractFinding,
    ReportParser,
)
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import key_index_error_handler


@dataclass
class AnchoreCVEFinding(AbstractFinding):
    """Supports gathering metadata for anchore cve findings Can be initialized
    directly from anchore cve finding json passed as kwargs."""

    tag: str = ""
    feed: str = ""
    feed_group: str = ""
    package_type: str = ""
    package_version: str = ""
    fix: str = ""
    url: str = ""
    extra: dict[str, Any] = field(default_factory=lambda: {})
    inherited_from_base: str = "no_data"
    nvd_data: list[dict[str, Any]] | dict[str, Any] = field(default_factory=lambda: [])
    vendor_data: list[dict[str, Any]] = field(default_factory=lambda: [])
    # values are parsed form key paths in anchore report
    identifiers: list[str] = field(default_factory=lambda: [])
    description: str = "none"
    # use old format for scan report parsing
    scan_source: str = "anchore_cve"
    nvd_cvss_v2_vector: str | None = None
    nvd_cvss_v3_vector: str | None = None
    vendor_cvss_v2_vector: str | None = None
    vendor_cvss_v3_vector: str | None = None
    # used only within the module
    _nvd_versions: list = field(default_factory=lambda: ["v2", "v3"])
    _log: logger = logger.setup("AnchoreCVEFindingParser")

    def __post_init__(self):
        """Set values from existing object attributes that were set during
        __init__"""

        # allow for multiple names for vuln, allows vat/csv_gen to use different names and parse __dict__ for an AnchoreCVEFinding object
        self.set_sorted_fix()
        self.identifiers.append(self.vuln)
        # intentionally throw key error if description doesn't exist
        # "or" evaluates on extra["description"] is some falsey value
        self.description = self.extra["description"] or self.description
        for ver in self._nvd_versions:
            self.set_nvd_scores(ver)
            self.set_vendor_nvd_scores(ver)
        self.set_identifiers()
        # no_data is set in the init by default, but if the value for inherited_from_base is "" or some other falsey value, update it to no_data
        self.inherited_from_base = self.inherited_from_base or "no_data"

    # We might want to add accessors/mutators for these properties in the future
    # For now, we'll only be using these properties as aliases for other initialized/updated attributes of this class
    # If we decide to use these, we can uncomment the following lines for "inherited"
    # @inherited.setter
    # def inherited(self, new_assignment):
    #     self.inherited_from_base = new_assignment

    # @inherited.deleter
    # def inherited(self):
    #     del self.inherited_from_base

    @property
    def cve(self) -> str:
        """Read only alias for identifier."""
        return self.identifier

    @property
    def vuln(self) -> str:
        return self.identifier

    @property
    def inherited(self) -> str:
        """Read only alias for inherited_from_base."""
        return self.inherited_from_base

    @property
    def link(self) -> str:
        """Read only alias for url."""
        return self.url

    @classmethod
    def from_dict(cls, vuln_data: dict[str, Any]) -> object:
        """Generate object from dictionary representation of anchore cve
        finding."""
        return cls(
            **{k: v for k, v in vuln_data.items() if k in [f.name for f in fields(cls)]}
        )

    @key_index_error_handler
    def set_nvd_scores(self, version: str) -> None:
        """Set nvd vector scores for multiple versions."""
        if self.extra["nvd_data"][0][f"cvss_{version}"]:
            setattr(
                self,
                f"nvd_cvss_{version}_vector",
                self.extra["nvd_data"][0]
                .get(f"cvss_{version}", {})
                .get("vector_string", None),
            )

    @key_index_error_handler
    def set_vendor_nvd_scores(self, version: str) -> None:
        """Set nvd vendor vector scores for multiple versions."""
        for d in self.extra["vendor_data"]:
            if d.get(f"cvss_{version}") and d.get(f"cvss_{version}").get(
                "vector_string"
            ):
                setattr(
                    self,
                    f"vendor_cvss_{version}_vector",
                    d[f"cvss_{version}"]["vector_string"],
                )

    @key_index_error_handler
    def set_identifiers(self) -> None:
        """Set identifiers from additional nvd data."""
        if self.nvd_data:
            if isinstance(self.nvd_data, list) and len(self.nvd_data):
                if self.nvd_data[0]["id"] != self.identifier:
                    self.identifiers.append(self.nvd_data[0]["id"])
            elif self.nvd_data["id"] != self.identifier:
                self.identifiers.append(self.nvd_data["id"])
        else:
            if self.vendor_data[0]["id"] != self.identifier:
                self.identifiers.append(self.vendor_data[0]["id"])

    def set_truncated_url(self, max_url_len: int = 65535) -> None:
        """Truncate url to prevent issues with vat import Size for url value
        must be less than `max_url_len` to prevent errors while importing to
        VAT.

        The following should always evaluate to false since we no longer
        use vulndb as a data source for anchore Keeping this logic in
        case this issue occurs again or we start using vulndb again
        """
        link_string = ""
        if isinstance(self.url, list):
            for url in self.url:
                url_text = f"{url['source']}:{url['url']}\n"
                if (len(url_text) + len(link_string)) < max_url_len:
                    link_string += url_text
                else:
                    self._log.warning(
                        "Unable to add all reference URLs to API POST. Please refer to anchore_security.json for more info."
                    )
                    break
            self.url = link_string
        # else, skip truncation

    def set_sorted_fix(self) -> None:
        """Convert fix field from unsorted string to sorted list of fixes as
        comma separated string."""
        fix_version_re: str = r"([A-Za-z0-9][-.0-~]*)"
        fix_list: list[str] = re.findall(fix_version_re, self.fix)
        self.fix = ", ".join(sorted(fix_list))

    def as_dict(self) -> dict[str, Any]:
        """Return object as dictionary containing attributes and properties."""
        return {
            "cve": self.cve,
            "vuln": self.vuln,
            **super().as_dict(),
            "link": self.link,
            "inherited": self.inherited,
        }


@dataclass
class AnchoreReportParser(ReportParser):
    """Class for parsing findings out of anchore cve and compliance reports
    (compliance not yet implemented)"""

    log: logger = logger.setup("AnchoreReportParser")

    @classmethod
    def get_findings(cls, report_path: Path) -> list[AnchoreCVEFinding]:
        """Gather anchore findings from anchore json report."""
        findings = []
        scan_json: dict = json.loads(report_path.read_text())
        for vuln_data in scan_json["vulnerabilities"]:
            # change vuln to identifier to match attributes
            vuln_data["identifier"] = vuln_data["vuln"]
            anchore_vuln = AnchoreCVEFinding.from_dict(
                vuln_data={**vuln_data, "tag": scan_json["imageFullTag"]}
            )
            findings.append(anchore_vuln)

        cls.log.info("Vulnerabilities retrieved")
        return findings
