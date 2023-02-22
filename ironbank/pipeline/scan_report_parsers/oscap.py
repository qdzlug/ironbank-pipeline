from abc import abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from ironbank.pipeline.scan_report_parsers.report_parser import (
    ReportParser,
    AbstractFinding,
)
import xml.etree.ElementTree as etree

from ironbank.pipeline.utils import logger
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
    identifiers: list = field(default_factory=lambda: [])
    result: str = None
    references: str = None
    rationale: str = None
    scanned_date: str = None
    justification: str = None
    _log: logger = logger.setup("OscapComplianceFinding")
    _oval_rule: str = "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"
    namespaces: ClassVar[dict[str, str]] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
    }

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

    # def _get_identifiers

    @classmethod
    @abstractmethod
    def from_rule_result(cls, root, rule_result):
        pass

    @classmethod
    def get_findings_from_rule_result(cls, root, rule_result) -> list:
        """
        Gather findings from single rule_result
        If rule_result iss OVAL, this list could include several findings, if rule_result is compliance only one finding will be returned in the list
        """
        # rule_id = rule_result.attrib["idref"]
        # severity = rule_result.attrib["severity"]
        finding_class = (
            OscapOVALFinding
            if rule_result.attrib["idref"] == cls._oval_rule
            else OscapComplianceFinding
        )
        findings = finding_class.from_rule_result(root=root, rule_result=rule_result)
        return findings if isinstance(findings, list) else [findings]


@dataclass(slots=True, frozen=True, eq=True)
class OscapComplianceFinding(OscapFinding):
    @classmethod
    def get_identifiers(cls, rule):
        return [ident.text for ident in rule.findall("xccdf:ident", cls.namespaces)]

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
        return "\n".join(
            cls._format_reference(ref)
            for ref in rule.findall("xccdf:reference", cls.namespaces)
        )

    @classmethod
    def get_rationale(cls, rule):
        rationale_element = rule.find("xccdf:rationale", cls.namespaces)
        return (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

    @classmethod
    def from_rule_result(cls, root, rule_result) -> object:
        """
        Generate a single compliance finding from a rule result
        TODO: add notes on difference between root, rule, and rule_result
        """
        rule_id = rule_result.attrib["idref"]
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", cls.namespaces)
        identifiers = cls.get_identifiers(rule) or [rule_id]
        return cls(
            identifier=identifiers[0],
            identifiers=identifiers,
            severity=rule_result.attrib["severity"].lower(),
            rule_id=rule_id,
            title=rule.find("xccdf:title", cls.namespaces).text,
            description=cls.get_description(rule),
            references=cls.get_references(rule),
            rationale=cls.get_rationale(rule),
            scanned_date=rule_result.attrib["time"],
            result=rule_result.find("xccdf:result", cls.namespaces).text,
        )


@dataclass(slots=True, frozen=True)
class OscapOVALFinding(OscapFinding):
    @classmethod
    def from_rule_result(cls, root, rule_result) -> list[object]:
        """
        Generate a list of OVAL findings from a rule result
        """
        return cls.__name__

    def __eq__(self, other):
        """
        Prevent having multiple oval findings with same identifier
        """
        return self.identifier == other.identifier


@dataclass
class OscapComplianceParser(ReportParser):
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
        return flatten(
            [
                OscapFinding.get_findings_from_rule_result(root, rule_result)
                for rule_result in failed_compliance_results
            ]
        )
