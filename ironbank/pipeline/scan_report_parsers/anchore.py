# maybe security and gate parsers should be separate

import json
from pathlib import Path
import re
from dataclasses import dataclass, field, fields
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import key_index_error_handler
from ironbank.pipeline.scan_report_parsers.report_parser import (
    AbstractFinding,
    ReportParser,
)


@dataclass(slots=True, frozen=True)
class AnchoreCVEFinding(AbstractFinding):
    # keys match anchore severity report, passed as kwargs
    tag: str
    identifier: str
    severity: str
    feed: str
    feed_group: str
    package: str
    package_path: str
    package_type: str
    package_version: str
    fix: str
    url: str
    extra: dict
    inherited_from_base: str = "no_data"
    nvd_data: list = field(default_factory=lambda: [])
    vendor_data: list = field(default_factory=lambda: [])
    # values are parsed form key paths in anchore report
    identifiers: list[str] = field(default_factory=lambda: [])
    description: str = "none"
    # use old format for scan report parsing
    scan_source: str = "anchore_cve"
    nvd_cvss_v2_vector: str = None
    nvd_cvss_v3_vector: str = None
    vendor_cvss_v2_vector: str = None
    vendor_cvss_v3_vector: str = None
    # used only within the module
    _nvd_versions: list = field(default_factory=lambda: ["v2", "v3"])
    _log: logger = logger.setup("AnchoreCVEFindingParser")

    def __post_init__(self):
        """
        Set values from existing object attributes that were set during __init__
        """
        # TODO: switch these to setattr to prevent issues with frozen

        # allow for multiple names for vuln, allows vat/csv_gen to use different names and parse __dict__ for an AnchoreCVEFinding object
        self.sort_fix()
        self.identifiers.append(self.vuln)
        # intentionally throw key error if description doesn't exist
        # "or" evaluates on extra["description"] is some falsey value
        self.description = self.extra["description"] or self.description
        for ver in self._nvd_versions:
            self.get_nvd_scores(ver)
            self.get_vendor_nvd_scores(ver)
        self.get_identifiers()
        # no_data is set in the init by default, but if the value for inherited_from_base is "" or some other falsey value, update it to no_data
        self.inherited_from_base = self.inherited_from_base or "no_data"

    # add alias from inherited -> inherited_from_base
    @property
    def inherited(self):
        return self.inherited_from_base

    # We might want to add accessors/mutators for these properties in the future
    # For now, we'll only be using these properties as aliases for other initialized/updated attributes of this class
    # If we decide to use these, we can uncomment the following lines for "inherited"
    # @inherited.setter
    # def inherited(self, new_assignment):
    #     self.inherited_from_base = new_assignment

    # @inherited.deleter
    # def inherited(self):
    #     del self.inherited_from_base

    # add alias from finding -> vuln
    @property
    def finding(self):
        return self.vuln

    # add alias from cve -> vuln
    @property
    def cve(self):
        return self.identifier

    @property
    def vuln(self):
        return self.identifier

    @property
    def packagePath(self):
        return self.package_path

    @property
    def scanSource(self):
        return self.scan_source

    @property
    def link(self):
        return self.url

    @classmethod
    def from_dict(cls, vuln_data):
        # only use keys from vuln_data supported by the AnchoreCVEFinding class init
        return cls(
            **{k: v for k, v in vuln_data.items() if k in [f.name for f in fields(cls)]}
        )

    @key_index_error_handler
    def get_nvd_scores(self, version):
        if self.extra["nvd_data"][0][f"cvss_{version}"]:
            setattr(
                self,
                f"nvd_cvss_{version}_vector",
                self.extra["nvd_data"][0]
                .get(f"cvss_{version}", {})
                .get("vector_string", None),
            )

    @key_index_error_handler
    def get_vendor_nvd_scores(self, version):
        for d in self.extra["vendor_data"]:
            if d.get(f"cvss_{version}") and d.get(f"cvss_{version}").get(
                "vector_string"
            ):
                setattr(
                    self,
                    f"vendor_cvss_{version}_vector",
                    d[f"cvss_{version}"]["vector_string"],
                )

    # def get_justification():
    @key_index_error_handler
    def get_identifiers(self):
        if self.nvd_data:
            if isinstance(self.nvd_data, list) and len(self.nvd_data):
                if self.nvd_data[0]["id"] != self.identifier:
                    self.identifiers.append(self.nvd_data[0]["id"])
            elif self.nvd_data["id"] != self.identifier:
                self.identifiers.append(self.nvd_data["id"])
        else:
            if self.vendor_data[0]["id"] != self.identifier:
                self.identifiers.append(self.vendor_data[0]["id"])

    def get_truncated_url(self, max_url_len: int = 65535):
        link_string = ""
        # The following should always evaluate to false since we no longer use vulndb as a data source for anchore
        # Keeping this logic in case this issue occurs again or we start using vulndb again
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

    def sort_fix(self):
        fix_version_re = "([A-Za-z0-9][-.0-~]*)"
        fix_list = re.findall(fix_version_re, self.fix)
        self.fix = ", ".join(sorted(fix_list))

    def as_dict(self):
        return {
            "finding": self.finding,
            "cve": self.cve,
            "vuln": self.vuln,
            **super().as_dict(),
            "packagePath": self.packagePath,
            "link": self.link,
            "inherited": self.inherited,
            "scanSource": self.scanSource,
        }


@dataclass
class AnchoreSecurityParser(ReportParser):
    log: logger = logger.setup("AnchoreSecurityParser")

    @classmethod
    def get_findings(cls, report_path: Path):
        findings = []
        scan_json = json.loads(report_path.read_text())
        for vuln_data in scan_json["vulnerabilities"]:
            anchore_vuln = AnchoreCVEFinding.from_dict(
                vuln_data={**vuln_data, "tag": scan_json["imageFullTag"]}
            )
            findings.append(anchore_vuln)
        cls.log.info("Vulnerabilities retrieved")
        return list(set(findings))
