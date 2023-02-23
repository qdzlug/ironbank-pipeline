from abc import abstractmethod
import bz2
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import ClassVar

import requests
from ironbank.pipeline.scan_report_parsers.report_parser import (
    ReportParser,
    AbstractFinding,
)
import xml.etree.ElementTree as etree

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import (
    NoMatchingOvalUrl,
    OvalDefintionDownloadFailure,
)
from ironbank.pipeline.utils.flatten import flatten


@dataclass(slots=True, frozen=True)
class OscapFinding(AbstractFinding):
    identifier: str
    severity: str
    description: str
    rule_id: str = None
    score: str = ""
    link: str = None
    package: str = None
    package_path: str = None
    title: str = None
    scan_source: str = "oscap_comp"
    identifiers: tuple = field(default_factory=lambda: ())
    result: str = None
    references: str = None
    rationale: str = None
    scanned_date: str = None
    justification: str = None
    namespaces: ClassVar[dict[str, str]] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
        "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    }
    _oval_rule: ClassVar[
        str
    ] = "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"

    @classmethod
    def get_findings_from_rule_result(cls, root, rule_result) -> list[object]:
        """
        Gather findings from single rule_result
        If rule_result iss OVAL, this list could include several findings, if rule_result is compliance only one finding will be returned in the list
        """
        finding_class = (
            OscapOVALFinding
            if rule_result.attrib["idref"] == cls._oval_rule
            else OscapComplianceFinding
        )
        print(rule_result.attrib["idref"])
        return finding_class.get_findings_from_rule_result(
            root=root, rule_result=rule_result
        )

    @property
    def desc(self):
        return self.description

    @property
    def refs(self):
        return self.references

    @classmethod
    def _format_reference(cls, ref):
        ref_title = ref.find("dc:title", cls.namespaces)
        ref_identifier = ref.find("dc:identifier", cls.namespaces)
        if ref_title is not None:
            assert ref_identifier is not None
            return f"{ref_title.text}: {ref_identifier.text}"
        return ref.text

    def __hash__(self):
        return hash(self.identifier)


@dataclass(slots=True, frozen=True, eq=True)
class OscapComplianceFinding(OscapFinding):
    _log: logger = logger.setup("OscapComplianceFinding")

    @classmethod
    def get_identifiers(cls, rule, rule_id) -> tuple:
        identifiers = tuple(
            ident.text for ident in rule.findall("xccdf:ident", cls.namespaces)
        ) or [rule_id]
        assert len(identifiers) == 1
        return identifiers

    @classmethod
    def get_description(cls, rule):
        return (
            etree.tostring(
                rule.find("xccdf:description", cls.namespaces), method="text"
            )
            .decode("utf8")
            .strip()
        )

    @classmethod
    def get_references(cls, rule):
        references = "\n".join(
            cls._format_reference(ref)
            for ref in rule.findall("xccdf:reference", cls.namespaces)
        )
        assert references
        return references

    @classmethod
    def get_rationale(cls, rule):
        rationale_element = rule.find("xccdf:rationale", cls.namespaces)
        return (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

    @classmethod
    def get_findings_from_rule_result(cls, root, rule_result) -> list[object]:
        """
        Generate a single compliance finding from a rule result
        TODO: add notes on difference between root, rule, and rule_result
        """
        rule_id = rule_result.attrib["idref"]
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", cls.namespaces)
        identifiers = cls.get_identifiers(rule, rule_id)
        return [
            cls(
                identifier=identifiers[0],
                identifiers=identifiers,
                severity=rule_result.attrib["severity"].lower(),
                rule_id=rule_id,
                title=rule.find("xccdf:title", cls.namespaces).text,
                scanned_date=rule_result.attrib["time"],
                result=rule_result.find("xccdf:result", cls.namespaces).text,
                description=cls.get_description(rule),
                references=cls.get_references(rule),
                rationale=cls.get_rationale(rule),
            )
        ]


@dataclass(slots=True, frozen=True)
class OscapOVALFinding(OscapFinding):
    _log: logger = logger.setup("OscapOVALFinding")

    @classmethod
    def get_findings_from_rule_result(cls, root, rule_result) -> list[object]:
        """
        Generate a list of OVAL findings from a rule result
        """
        oval_name_href = {
            f"finding_{attr}": rule_result.find(
                "xccdf:check/xccdf:check-content-ref", cls.namespaces
            ).attrib[attr]
            for attr in ["name", "href"]
        }
        return cls.get_oval_findings(
            **oval_name_href, severity=rule_result.attrib["severity"].lower()
        )

    @classmethod
    def get_oval_url(cls, finding_href):
        if rhel_match := re.search(r"RHEL(?P<version>(7|8|9))", finding_href):
            return f"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{rhel_match.group('version')}.xml.bz2"
        elif sle_match := re.search(
            r"suse\.linux\.enterprise\.(?P<version>(15))", finding_href
        ):
            return f"https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.{sle_match.group('version')}-patch.xml"
        else:
            cls._log.error("OVAL findings found for unknown image type")
            raise NoMatchingOvalUrl

    @classmethod
    def download_oval_defintions(cls, url: str) -> list[dict]:
        """ """
        artifact_path = Path(
            f"{os.environ['ARTIFACT_DIR']}/oval_definitions-{re.sub(r'[^a-z]', '-', url)}.xml"
        )
        if not artifact_path.exists():
            response = requests.get(url, stream=True, timeout=None)
            if response.status_code == 200:
                with Path(artifact_path).open("wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                if url.endswith(".bz2"):
                    data = bz2.BZ2File(artifact_path).read()
                    data_string = str(data, "utf-8")
                    Path(artifact_path).write_text(data_string, encoding="utf-8")
            else:
                cls._log.info(
                    "Failed to download oval definitions: %s", response.status_code
                )
                raise OvalDefintionDownloadFailure
        return artifact_path

    @classmethod
    def get_oval_findings(cls, finding_name, finding_href, severity) -> list[object]:
        url = cls.get_oval_url(finding_href)
        root = etree.parse(cls.download_oval_defintions(url))

        findings: list[OscapOVALFinding] = []
        definition = root.find(
            f".//oval:definition[@id='{finding_name}']", cls.namespaces
        )
        for finding in definition.findall(
            "oval:metadata/oval:advisory/oval:cve", cls.namespaces
        ):
            findings.append(
                cls(
                    identifier=finding.text,
                    link=finding.attrib["href"],
                    description=definition.find(
                        "oval:metadata/oval:title", cls.namespaces
                    ).text,
                    severity=severity,
                )
            )
        return findings

    def __eq__(self, other):
        """
        Prevent having multiple oval findings with same identifier
        """
        return self.identifier == other.identifier


@dataclass
class OscapReportParser(ReportParser):
    log: logger = logger.setup("OscapComplianceParser")

    @classmethod
    def get_findings(cls, scan_xml: Path) -> list[OscapComplianceFinding]:
        root = etree.parse(scan_xml)
        failed_compliance_results = [
            rule_result
            for rule_result in root.findall(
                "xccdf:TestResult/xccdf:rule-result", OscapFinding.namespaces
            )
            if rule_result.find("xccdf:result", OscapFinding.namespaces).text
            in ["notchecked", "fail", "error"]
        ]
        oscap_findings = flatten(
            [
                OscapFinding.get_findings_from_rule_result(root, rule_result)
                for rule_result in failed_compliance_results
            ]
        )
        # remove duplicates
        return list(set(oscap_findings))
