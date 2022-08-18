# maybe security and gate parsers should be separate

import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import key_index_error_handler


@dataclass
class AnchoreVuln:
    # keys match anchore severity report, passed as kwargs
    tag: str
    vuln: str
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
    nvd_cvss_v2_vector: str = None
    nvd_cvss_v3_vector: str = None
    vendor_cvss_v2_vector: str = None
    vendor_cvss_v3_vector: str = None
    justification: str = None
    # used only within the module
    _nvd_versions: list = field(default_factory=lambda: ["v2", "v3"])
    _log: logger = logger.setup("AnchoreVulnParser")

    def __post_init__(self):
        self.identifiers.append(self.vuln)
        self.description = self.extra["description"] or self.description
        for ver in self._nvd_versions:
            self.get_nvd_scores(ver)
            # self.get_vendor_nvd_scores(ver)
        self.get_identifiers()

    @classmethod
    def from_dict(cls, vuln_data):
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
            if d.get(f"cvss_{version}", "").get("vector_string"):
                setattr(
                    self,
                    f"vendor_cvss_{version}_vector",
                    d[f"cvss_{version}"]["vendor_string"],
                )

    # def get_justification():
    @key_index_error_handler
    def get_identifiers(self):
        if self.nvd_data:
            if isinstance(self.nvd_data, list) and len(self.nvd_data):
                if self.nvd_data[0]["id"] != self.vuln:
                    self.identifiers.append(self.nvd_data[0]["id"])
            elif self.nvd_data["id"] != self.vuln:
                self.identifiers.append(self.nvd_data["id"])
        else:
            if self.vendor_data[0]["id"] != self.vuln:
                self.identifiers.append(self.vendor_data[0]["id"])

    def get_truncated_url(self, max_url_len: int = 65535):
        link_string = ""
        if isinstance(self.url, list):
            for url in self.url:
                url_text = f"{url['source']}:{url['url']}\n"
                if len(url_text + link_string) > max_url_len:
                    link_string += url_text
                else:
                    self._log.warning(
                        "Unable to add all reference URLs to API POST. Please refer to anchore_security.json for more info."
                    )
                    break
            self.url = link_string

    def sort_fix(self):
        fix_version_re = "([A-Za-z0-9][-.0-~]*)"
        fix_list = re.findall(fix_version_re, self.fix)
        self.fix = ", ".join(sorted(fix_list))


@dataclass
class AnchoreSecurityParser:
    log: logger = logger.setup("AnchoreSecurityParser")

    @classmethod
    def get_vulnerabilities(cls, scan_json):
        vulnerabilities = []
        for vuln_data in scan_json["vulnerabilities"]:
            anchore_vuln = AnchoreVuln.from_dict(
                vuln_data={**vuln_data, "tag": scan_json["imageFullTag"]}
            )
            vulnerabilities.append(anchore_vuln)
        cls.log.info("Vulnerabilities retrieved")
        return vulnerabilities
