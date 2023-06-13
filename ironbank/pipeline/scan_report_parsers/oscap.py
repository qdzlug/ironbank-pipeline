import bz2
import os
import re
import xml.etree.ElementTree as etree
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any, Callable, ClassVar, Generator, Optional
from xml.etree.ElementTree import Element, ElementTree

import requests

from ironbank.pipeline.scan_report_parsers.report_parser import (
    AbstractFinding,
    ReportParser,
)
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import (
    NoMatchingOvalUrl,
    OvalDefinitionDownloadFailure,
)
from ironbank.pipeline.utils.flatten import flatten


@dataclass
class RuleInfo:
    """Helper class to support gathering everything from the oscap compliance
    xml document All xml parsing for compliance document should be done within
    this class."""

    root: InitVar[ElementTree]
    rule_result: InitVar[Element]
    rule_id: str = ""
    identifiers: list[str] | None = None
    identifier: str = ""
    title: str = ""
    severity: str = ""
    time: str = ""
    result: str = ""
    references: str = ""
    rationale: str = ""
    description: str = ""
    namespaces: ClassVar[dict[str, str]] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
        "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    }
    oval_rule: ClassVar[
        str
    ] = "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"
    pass_results: ClassVar[tuple[str]] = ("pass", "notapplicable")
    skip_results: ClassVar[tuple[str]] = "notselected"
    fail_results: ClassVar[tuple[str]] = ("notchecked", "fail", "error")
    oval_name: str = ""
    oval_href: str = ""
    _log: logger = logger.setup("RuleInfo")

    # TODO: consider making a separate factory for this purpose
    def __new__(
        cls, root: ElementTree, rule_result: Element, *args, **kwargs
    ) -> Callable:  # pylint: disable=unused-argument
        """RuleInfo constructor Supports using generic RuleInfo to select the
        appropriate class for constructing (RuleInfo or RuleInfoOVAL)
        Constructor accepts *args and **kwargs to support unit testing (setting
        rule_id), but these additional args are not used otherwise."""
        return object.__new__(
            RuleInfoOVAL
            if (cls.get_rule_id(rule_result) == cls.oval_rule)
            and (cls.get_result(rule_result) not in cls.pass_results)
            else RuleInfo
        )

    def __post_init__(self, root: ElementTree, rule_result: Element) -> None:
        """
        root: entire xml document tree structure
        rule_result: portion of xml tree defining the result of the rule in the scan
        rule: portion of xml tree providing information about the rule itself
        """
        self.rule_id = rule_result.attrib["idref"]
        rule: Element = root.find(
            f".//xccdf:Rule[@id='{self.rule_id}']", self.namespaces
        )
        self.set_identifiers(rule)
        self.title = rule.find("xccdf:title", self.namespaces).text
        self.severity = rule_result.attrib["severity"]
        self.time = rule_result.attrib["time"]
        self.set_result(rule_result)
        self.set_references(rule)
        self.set_rationale(rule)
        self.set_description(rule)

    @classmethod
    def _format_reference(cls, ref: Element) -> str:
        """Format reference element as title:identifier str."""
        ref_title: str = ref.find("dc:title", cls.namespaces)
        ref_identifier: str = ref.find("dc:identifier", cls.namespaces)
        if ref_title is not None:
            assert ref_identifier is not None
            return f"{ref_title.text}: {ref_identifier.text}"
        return ref.text

    def set_identifiers(self, rule: Element) -> None:
        """Set identifiers and identifier attribute from rule."""
        self.identifiers = tuple(
            ident.text for ident in rule.findall("xccdf:ident", self.namespaces)
        ) or [self.rule_id]
        assert len(self.identifiers) == 1
        self.identifier = self.identifiers[0]

    @classmethod
    def get_result(cls, rule_result: Element) -> str:
        """Get single compliance findings pass/fail/etc.

        result
        """
        return rule_result.find("xccdf:result", cls.namespaces).text

    def set_result(self, rule_result: Element) -> str:
        """Set result from rule_result."""
        self.result = self.get_result(rule_result=rule_result)

    def set_description(self, rule: Element) -> str:
        """Format and set description from rule."""
        self.description = (
            etree.tostring(
                rule.find("xccdf:description", self.namespaces), method="text"
            )
            .decode("utf8")
            .strip()
        )

    def set_references(self, rule: Element) -> str:
        """Format and set reference from rule."""
        self.references = "\n".join(
            self._format_reference(ref)
            for ref in rule.findall("xccdf:reference", self.namespaces)
        )
        # assert self.references

    def set_rationale(self, rule: Element) -> None:
        """Format and set rationale from rule."""
        rationale_element: Element = rule.find("xccdf:rationale", self.namespaces)
        self.rationale = (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

    @classmethod
    def get_rule_id(cls, rule_obj: Element) -> str:
        """Get rule id from either rule or rule_result."""
        return rule_obj.attrib.get("id", "") or rule_obj.attrib.get("idref", "")

    @classmethod
    def get_results(cls, root: ElementTree, results_filter: list[str]) -> list[Element]:
        """Get results based on filter If results_filter is falsey, return all
        selected results Else return all results matching result values in
        results filter.

        Examples:
        - get_results(cls, root, ["pass"]) will return all elements which contain a result value of pass
        - get_results(cls, root, RuleInfo.fail_results) will return all elements that have failed due to ("notchecked", "fail", etc.)
        """
        return [
            rule_result
            for rule_result in root.findall(
                "xccdf:TestResult/xccdf:rule-result", cls.namespaces
            )
            if (
                (cls.get_result(rule_result) in results_filter)
                if results_filter
                else (cls.get_result(rule_result) not in cls.skip_results)
            )
        ]


class RuleInfoOVAL(RuleInfo):
    """Extension of RuleInfo compliance xml parsing class to support parsing
    oval xml All oval xml parsing should be done within this class."""

    oval_name: str | None = None
    oval_href: str | None = None
    # definition
    definition: Element | None = None
    findings: str | None = None
    description: str | None = None
    _log: logger = logger.setup("RuleInfoOVAL")

    def __new__(cls, root: ElementTree, rule_result: Element, *args, **kwargs):
        """RuleInfoOVAL Implemented to document use case for the base
        constructor and to provide functionality if needed Constructor accepts
        *args and **kwargs to support unit testing (setting rule_id), but these
        additional args are not used otherwise."""
        cls._log.warning(
            "Constructing RuleInfoOVAL directly. While this is supported you'll likely want to use the base RuleInfo class to automatically select the appropriate class for instantiation"
        )
        return object.__new__(cls)

    def __post_init__(self, root: ElementTree, rule_result: Element) -> None:
        """Get all compliance info for finding Get oval info from compliance
        document."""
        super().__post_init__(root, rule_result)
        self.set_oval_name(rule_result)
        self.set_oval_href(rule_result)
        oval_url: str = self.get_oval_url(self.oval_href)
        oval_root: ElementTree = etree.parse(self.download_oval_definitions(oval_url))
        self.set_values_from_oval_report(oval_root)

    def set_oval_val_from_ref(self, val: str, rule_result: Element) -> None:
        """Helper function for setting oval name and href."""
        setattr(
            self,
            f"oval_{val}",
            rule_result.find(
                "xccdf:check/xccdf:check-content-ref", self.namespaces
            ).attrib[val],
        )

    def set_oval_name(self, rule_result: Element) -> None:
        """Set oval name from compliance document."""
        self.set_oval_val_from_ref("name", rule_result)

    def set_oval_href(self, rule_result: Element) -> None:
        """Set oval href from compliance document."""
        self.set_oval_val_from_ref("href", rule_result)

    def set_values_from_oval_report(self, oval_root: ElementTree) -> None:
        """Update object values from oval xml."""
        self.set_definition(oval_root)
        self.set_findings()
        self.set_description()

    def set_definition(self, oval_root: ElementTree) -> None:
        """Set definition from oval report."""
        self.definition = oval_root.find(
            f".//oval:definition[@id='{self.oval_name}']", self.namespaces
        )

    def set_findings(self) -> None:
        """Set findings from oval report."""
        self.findings = self.definition.findall(
            "oval:metadata/oval:advisory/oval:cve", self.namespaces
        )

    def set_description(self, *args, **kwargs) -> None:
        """When first initializing (i.e. calling super().__post_init__), use
        compliance method to set description Once parent initializition
        finishes, set the updated description from the oval report."""
        if args or kwargs:
            super().set_description(*args, **kwargs)
        else:
            self.description = self.definition.find(
                "oval:metadata/oval:title", self.namespaces
            ).text

    @classmethod
    def get_oval_url(cls, finding_href: str) -> str:
        """Gather oval url from os type Only called if an OVAL finding is
        discovered."""
        if rhel_match := re.search(r"RHEL(?P<version>(7|8|9))", finding_href):
            return f"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{rhel_match.group('version')}.xml.bz2"
        if sle_match := re.search(
            r"suse\.linux\.enterprise\.(?P<version>(15))", finding_href
        ):
            return f"https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.{sle_match.group('version')}-patch.xml"

        cls._log.error("OVAL findings found for unknown image type")
        raise NoMatchingOvalUrl

    @classmethod
    def download_oval_definitions(cls, url: str) -> Path:
        """Download oval definition if not already downloaded Only called if an
        OVAL finding is discovered."""
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
                raise OvalDefinitionDownloadFailure
        return artifact_path


@dataclass
class OscapFinding(AbstractFinding):
    """Base class for oscap findings Resolves finding type (compliance or OVAL)
    and methods properties to support gathering metadata from oscap
    findings."""

    rule_id: str | None = None
    score: str = ""
    package: str | None = None
    package_path: str | None = None
    references: str | None = None
    identifiers: tuple = field(default_factory=lambda: ())
    title: str | None = None
    result: str | None = None
    rationale: str | None = None
    scanned_date: str | None = None
    scan_source: str = "oscap_comp"

    @classmethod
    def get_default_init_params(cls, rule_info: RuleInfo) -> dict[str, Any]:
        """Return dictionary of default initialization paramaters."""
        return {
            "identifiers": rule_info.identifiers,
            "identifier": rule_info.identifier,
            "severity": rule_info.severity,
            "rule_id": rule_info.rule_id,
            "title": rule_info.title,
            "scanned_date": rule_info.time,
            "result": rule_info.result,
            "description": rule_info.description,
            "references": rule_info.references,
            "rationale": rule_info.rationale,
        }

    @classmethod
    def get_findings_from_rule_info(
        cls, rule_info: RuleInfo
    ) -> Generator[object, None, None]:
        """Gather findings from single rule_result If rule_result is OVAL, this
        list could include several findings, if rule_result is compliance only
        one finding will be returned in the generator."""
        finding_class = (
            OscapOVALFinding
            if isinstance(rule_info, RuleInfoOVAL)
            else OscapComplianceFinding
        )
        return finding_class.get_findings_from_rule_info(rule_info=rule_info)

    @property
    def desc(self) -> None:
        """Read only description alias."""
        return self.description

    @property
    def refs(self) -> None:
        """Read only references alias."""
        return self.references

    @property
    def ruleid(self) -> None:
        """Read only rule_id alias."""
        return self.rule_id

    def as_dict(self) -> dict[str, Any]:
        """Return object properties and attributes as a dictionary."""
        return {
            **super().as_dict(),
            "refs": self.refs,
            "desc": self.desc,
            "ruleid": self.ruleid,
        }


@dataclass(eq=True)
class OscapComplianceFinding(OscapFinding):
    """The OscapComplianceFinding class extends the OscapFinding class, and
    represents a single compliance finding from OpenSCAP.

    It is initialized with a logger object.

    Class Method:
    - get_findings_from_rule_info(cls, rule_info: RuleInfo) -> Generator[object, None, None]:
        Given a RuleInfo object, it generates a single compliance finding.
    """

    _log: logger = logger.setup("OscapComplianceFinding")

    @classmethod
    def get_findings_from_rule_info(
        cls, rule_info: RuleInfo
    ) -> Generator[object, None, None]:
        """Generate a single compliance finding from a RuleInfo object.

        This method is not directly called for this class type anywhere
        but in the parent's matching method However, this method could
        be called directly for compliance findings if needed
        """
        yield cls(**cls.get_default_init_params(rule_info))


@dataclass
class OscapOVALFinding(OscapFinding):
    """The OscapOVALFinding class extends the OscapFinding class, and
    represents a list of OVAL (Open Vulnerability and Assessment Language)
    findings from OpenSCAP.

    Class Method:
    - get_findings_from_rule_info(cls, rule_info: RuleInfoOVAL) -> Generator[object, None, None]:
        Given a RuleInfoOVAL object, it generates a list of OVAL findings.
    """

    link: str = None
    _log: logger = logger.setup("OscapOVALFinding")

    @classmethod
    def get_findings_from_rule_info(
        cls, rule_info: RuleInfoOVAL
    ) -> Generator[object, None, None]:
        """Generate a list of OVAL findings from a rule result.

        This method is not directly called for this class type anywhere
        but in the parent's matching method However, this method could
        be called directly for oval findings if needed
        """
        for finding in rule_info.findings:
            yield cls(
                **{
                    **cls.get_default_init_params(rule_info),
                    "identifier": finding.text,
                    "link": finding.attrib["href"],
                }
            )


@dataclass
class OscapReportParser(ReportParser):
    """Class for parsing findings out of oscap compliance reports."""

    log: logger = logger.setup("OscapReportParser")

    @classmethod
    def get_findings(
        cls,
        report_path: Path,
        results_filter: Optional[tuple[str]] = RuleInfo.fail_results,
    ) -> list[OscapComplianceFinding]:
        """Gather oscap finding from oscap xml report.

        If results_filter is None, all results will be returned if
        failed or not typically findings are in ["notchecked", "fail",
        "error"], but pipeline_csv_gen gathers all findings regardless
        of status
        """
        root: ElementTree = etree.parse(report_path)

        compliance_results: list[Element] = RuleInfo.get_results(
            root, results_filter=results_filter
        )

        findings: list[OscapFinding | list[OscapFinding]] = []

        for rule_result in compliance_results:
            rule_info = RuleInfo(root, rule_result)
            findings += OscapFinding.get_findings_from_rule_info(rule_info)

        # flatten, dedupe and sort findings
        findings = flatten(findings)
        findings = cls.dedupe_findings_by_attr(findings, "identifier")
        assert len(set(f.identifier for f in findings)) == len(findings)
        return sorted(findings, key=lambda x: x.rule_id)
