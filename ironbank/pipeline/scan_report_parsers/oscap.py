from abc import abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from ironbank.pipeline.scan_report_parsers.report_parser import (
    ReportParser,
    AbstractFinding,
)
import xml.etree.ElementTree as etree

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.flatten import flatten


@dataclass
class OscapFinding(AbstractFinding):
    cce: str
    severity: str
    description: str
    link: str
    score: str
    package: str
    package_path: str
    scan_source: str = "oscap_comp"
    identifiers: list = field(default_factory=lambda: [])
    rule_id: str = None
    result: str = None
    refs: str = None
    rationale: str = None
    scanned_date: str = None
    justification: str = None
    _log: logger = logger.setup("OscapComplianceFinding")
    _oval_rule: str = "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"

    @property
    def title(self):
        return self.cce

    @property
    def desc(self):
        return self.description

    def _format_reference(self, ref, namespaces):
        ref_title = ref.find("dc:title", namespaces)
        ref_identifier = ref.find("dc:identifier", namespaces)
        if ref_title is not None:
            assert ref_identifier is not None
            return f"{ref_title.text}: {ref_identifier.text}"
        return ref.text

    # def _get_identifiers

    @classmethod
    @abstractmethod
    def from_result(cls, result, namespaces):
        pass

    @classmethod
    def get_findings_from_result(cls, result, namespaces) -> list:
        """
        Gather findings from single result
        If finding is OVAL, this list could include several results, if finding is compliance only one result will be returned in the list
        """
        rule_id = result.attrib["idref"]
        severity = result.attrib["severity"]
        print(rule_id)
        cls = (
            OscapOVALFinding
            if result.attrib["idref"] == cls._oval_rule
            else OscapComplianceFinding
        )
        return cls.from_result(result, namespaces)


class OscapComplianceFinding(OscapFinding):
    @classmethod
    def from_result(cls, result, namespaces) -> list:
        return cls.__name__


class OscapOVALFinding(OscapFinding):
    @classmethod
    def from_result(cls, result, namespaces) -> list:
        return cls.__name__


@dataclass
class OscapComplianceParser(ReportParser):
    log: logger = logger.setup("OscapComplianceParser")

    @classmethod
    def get_findings(cls, scan_xml: Path) -> list[OscapComplianceFinding]:
        namespaces: dict[str, str] = {
            "xccdf": "http://checklists.nist.gov/xccdf/1.2",
            "dc": "http://purl.org/dc/elements/1.1/",
        }
        root = etree.parse(scan_xml)
        failed_compliance_results = [
            rule_result
            for rule_result in root.findall(
                "xccdf:TestResult/xccdf:rule-result", namespaces
            )
            if rule_result.find("xccdf:result", namespaces).text
            in ["notchecked", "fail", "error"]
        ]
        return [
            OscapFinding.get_findings_from_result(result, namespaces)
            for result in failed_compliance_results
        ]
