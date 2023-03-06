import bz2
from dataclasses import InitVar, dataclass, field
import os
from pathlib import Path
import re
from typing import Any, ClassVar, Generator

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


@dataclass
class RuleInfo:
    root: InitVar[str]
    rule_result: InitVar[str]
    rule_id: str = ""
    identifiers: list[str] = None
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

    def __new__(cls, root, rule_result):
        rule_class = (
            RuleInfoOVAL
            if (cls.get_rule_id(rule_result) == cls.oval_rule)
            and (cls.get_result(rule_result) not in cls.pass_results)
            else RuleInfo
        )
        return object.__new__(rule_class)

    def __post_init__(self, root, rule_result):
        """
        root: entire xml document tree structure
        rule_result: portion of xml tree defining the result of the rule in the scan
        rule: portion of xml tree providing information about the rule itself
        """
        self.rule_id = rule_result.attrib["idref"]
        rule = root.find(f".//xccdf:Rule[@id='{self.rule_id}']", self.namespaces)
        self.set_identifiers(rule)
        self.title = rule.find("xccdf:title", self.namespaces).text
        self.severity = rule_result.attrib["severity"]
        self.time = rule_result.attrib["time"]
        self.set_result(rule_result)
        self.set_references(rule)
        self.set_rationale(rule)
        self.set_description(rule)

    @classmethod
    def _format_reference(cls, ref):
        ref_title = ref.find("dc:title", cls.namespaces)
        ref_identifier = ref.find("dc:identifier", cls.namespaces)
        if ref_title is not None:
            assert ref_identifier is not None
            return f"{ref_title.text}: {ref_identifier.text}"
        return ref.text

    def set_identifiers(self, rule) -> tuple:
        self.identifiers = tuple(
            ident.text for ident in rule.findall("xccdf:ident", self.namespaces)
        ) or [self.rule_id]
        assert len(self.identifiers) == 1
        self.identifier = self.identifiers[0]

    @classmethod
    def get_result(cls, rule_result):
        return rule_result.find("xccdf:result", cls.namespaces).text

    def set_result(self, rule_result):
        """
        Return result of rule check from compliance scan
        """
        self.result = rule_result.find("xccdf:result", self.namespaces).text

    def set_description(self, rule):
        self.description = (
            etree.tostring(
                rule.find("xccdf:description", self.namespaces), method="text"
            )
            .decode("utf8")
            .strip()
        )

    def set_references(self, rule):
        self.references = "\n".join(
            self._format_reference(ref)
            for ref in rule.findall("xccdf:reference", self.namespaces)
        )
        # assert self.references

    def set_rationale(self, rule):
        rationale_element = rule.find("xccdf:rationale", self.namespaces)
        self.rationale = (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

    @classmethod
    def get_rule_id(self, rule_obj):
        return rule_obj.attrib.get("id", "") or rule_obj.attrib.get("idref", "")

    @classmethod
    def get_results(cls, root, results_filter=None):
        return [
            rule_result
            for rule_result in root.findall(
                "xccdf:TestResult/xccdf:rule-result", cls.namespaces
            )
            if (
                (
                    rule_result.find("xccdf:result", cls.namespaces).text
                    in results_filter
                )
                if results_filter
                else (
                    rule_result.find("xccdf:result", cls.namespaces).text
                    not in cls.skip_results
                )
            )
        ]


class RuleInfoOVAL(RuleInfo):
    oval_name: str = None
    oval_href: str = None
    definition: str = None
    findings: str = None
    description: str = None

    def __post_init__(self, root, rule_result):
        super().__post_init__(root, rule_result)
        self.set_oval_name(rule_result)
        self.set_oval_href(rule_result)

    def set_oval_val_from_ref(self, val, rule_result):
        setattr(
            self,
            f"oval_{val}",
            rule_result.find(
                "xccdf:check/xccdf:check-content-ref", self.namespaces
            ).attrib[val],
        )

    def set_oval_name(self, rule_result):
        self.set_oval_val_from_ref("name", rule_result)

    def set_oval_href(self, rule_result):
        self.set_oval_val_from_ref("href", rule_result)

    def set_values_from_oval_report(self, oval_root):
        self.set_definition(oval_root)
        self.set_findings()
        self.set_description()

    def set_definition(self, oval_root):
        self.definition = oval_root.find(
            f".//oval:definition[@id='{self.oval_name}']", self.namespaces
        )

    def set_findings(self):
        self.findings = self.definition.findall(
            "oval:metadata/oval:advisory/oval:cve", self.namespaces
        )

    def set_description(self, *args, **kwargs):
        if args or kwargs:
            super().set_description(*args, **kwargs)
        else:
            self.description = self.definition.find(
                "oval:metadata/oval:title", self.namespaces
            ).text


@dataclass
class OscapFinding(AbstractFinding):
    rule_id: str = None
    score: str = ""
    package: str = None
    package_path: str = None
    references: str = None
    identifiers: tuple = field(default_factory=lambda: ())
    title: str = None
    result: str = None
    rationale: str = None
    scanned_date: str = None
    scan_source: str = "oscap_comp"

    @classmethod
    def get_default_init_params(cls, rule_info):
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
    def get_findings_from_rule_info(cls, rule_info) -> list[object]:
        """
        Gather findings from single rule_result
        If rule_result is OVAL, this list could include several findings, if rule_result is compliance only one finding will be returned in the list
        """
        finding_class = (
            OscapOVALFinding
            if isinstance(rule_info, RuleInfoOVAL)
            else OscapComplianceFinding
        )
        return finding_class.get_findings_from_rule_info(rule_info=rule_info)

    @property
    def desc(self):
        return self.description

    @property
    def refs(self):
        return self.references

    @property
    def ruleid(self):
        return self.rule_id

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "refs": self.refs,
            "desc": self.desc,
            "ruleid": self.ruleid,
        }


@dataclass(eq=True)
class OscapComplianceFinding(OscapFinding):
    _log: logger = logger.setup("OscapComplianceFinding")

    @property
    def refs(self):
        return self.references

    @classmethod
    def get_findings_from_rule_info(cls, rule_info) -> object:
        """
        Generate a single compliance finding from a rule result

        Attributes like description/references/etc. are gathered here instead of a __post_init__ because they depend on the rule object
        """
        yield cls(**cls.get_default_init_params(rule_info))

    def __hash__(self):
        return hash(self.identifier)


@dataclass(eq=True)
class OscapOVALFinding(OscapFinding):
    link: str = None
    _log: logger = logger.setup("OscapOVALFinding")

    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        """
        Generate a list of OVAL findings from a rule result
        """
        oval_url = cls.get_oval_url(rule_info.oval_href)
        oval_root = etree.parse(cls.download_oval_defintions(oval_url))
        rule_info.set_values_from_oval_report(oval_root)
        for finding in rule_info.findings:
            yield cls(
                **{
                    **cls.get_default_init_params(rule_info),
                    "identifier": finding.text,
                    "link": finding.attrib["href"],
                }
            )

    # TODO: decide where these make the most sense, not sure the finding class is the best spot
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

    def __eq__(self, other):
        """
        Prevent having multiple oval findings with same identifier
        """
        return self.identifier == other.identifier

    def __hash__(self):
        return hash(self.identifier)


@dataclass
class OscapReportParser(ReportParser):
    log: logger = logger.setup("OscapReportParser")

    @classmethod
    def get_findings(
        cls, report_path: Path, results_filter: tuple[str] = None
    ) -> list[OscapComplianceFinding]:
        """
        if results_filter is None, all results will be returned if failed or not
        typically findings are in ["notchecked", "fail", "error"], but pipeline_csv_gen gathers all findings regardless of status
        """
        root = etree.parse(report_path)

        compliance_results = RuleInfo.get_results(root, results_filter=results_filter)

        findings = []

        for rule_result in compliance_results:
            rule_info = RuleInfo(root, rule_result)
            findings += OscapFinding.get_findings_from_rule_info(rule_info)

        # flatten, dedupe and sort findings
        findings = flatten(findings)
        findings = cls.dedupe_findings_by_attr(findings, "identifier")
        assert len(set(f.identifier for f in findings)) == len(findings)
        return sorted(findings, key=lambda x: x.rule_id)
