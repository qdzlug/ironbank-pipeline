# maybe security and gate parsers should be separate

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import nvd_exception_handler


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
    # values are parsed form key paths in anchore report
    description: str = "none"
    nvd_cvss_v2_vector: str = None
    nvd_cvss_v3_vector: str = None
    vendor_cvss_v2_vector: str = None
    vendor_cvss_v3_vector: str = None
    justification: str = None
    nvd_versions: list = ["v2", "v3"]
    log: logger = logger.setup("AnchoreVulnParser")

    def __post_init__(self):
        self.description = self.extra["description"] or self.description

    @nvd_exception_handler
    def get_nvd_scores(self):
        for ver in self.nvd_versions:
            setattr(
                self,
                f"nvd_cvss_{ver}_vector",
                self.extra["nvd_data"][0][f"cvss_{ver}"]["vector_string"],
            )

    @nvd_exception_handler
    def get_vendor_nvd_scores(self):
        for ver in self.nvd_versions:
            for d in self.extra["vendor_data"]:
                if d.get(f"cvss_{ver}", "").get("vector_string"):
                    setattr(
                        self,
                        f"vendor_cvss_{ver}_vector",
                        d[f"cvss_{ver}"]["vendor_string"],
                    )

    # def get_justification():

    def sort_fix(self):
        fix_version_re = "([A-Za-z0-9][-.0-~]*)"
        fix_list = re.findall(fix_version_re, self.fix)
        self.fix = ", ".join(sorted(fix_list))


@dataclass
class AnchoreSecurityParser:
    imageFullTag: str
    file_path: Path
    vulnerabilities: list[AnchoreVuln] = field(default_factory=lambda: [])
    log: logger = logger.setup("AnchoreSecurityParser")

    def get_vulnerabilities(self):
        with self.file_path.open() as f:
            json_data = json.load(f)
        for vuln_data in json_data["vulnerabilities"]:
            anchore_vuln = AnchoreVuln(**{**vuln_data, "tag": self.imageFullTag})
            self.vulnerabilities.append(anchore_vuln)
