#!/usr/bin/env python3


from dataclasses import dataclass
from xml.etree import ElementTree
from ironbank.pipeline.scan_report_parsers.oscap import OscapReportParser,OscapOVALFinding, RuleInfo,OscapComplianceFinding
from ironbank.pipeline.test.mocks.mock_classes import MockPath
import pytest
from unittest.mock import patch
from xml.etree.ElementTree import ElementTree, Element
from typing import Callable
import logging
import pytest

from unittest import mock
from pathlib import Path
from ironbank.pipeline.utils import logger
from dataclasses import InitVar, dataclass, field

log = logger.setup("test_oscap")
 
@dataclass 
class MockOscapFinding:
    identifier: str = ""
    severity: str = ""
    identifiers: tuple = field(default_factory=lambda: ())
    def get_findings_from_rule_info(self):
        el = Element("")
        el.attrib["identifier"] = "id"
        return [OscapComplianceFinding(identifier='1', rule_id='rule1',severity=""),
        OscapComplianceFinding(identifier='2', rule_id='rule1',severity=""),
        OscapComplianceFinding(identifier='1', rule_id='rule2',severity=""),
        OscapComplianceFinding(identifier='3', rule_id='rule2',severity="")]
    
#  identifier: str
#     severity: str
    
@dataclass 
class MockRuleInfo:
    def __new__(
        cls, root: ElementTree, rule_result: Element
    ) -> Callable:  # pylint: disable=unused-argument
      pass
    def __post_init__(self, root: ElementTree, rule_result: Element):
        pass
    
    def get_results(self, results_filter: list[str]):
        return [Element(""),Element(""),Element("")]
    
    


@pytest.mark.only
@patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", new=MockRuleInfo)
@patch("ironbank.pipeline.scan_report_parsers.oscap.OscapFinding", new=MockOscapFinding)
def test_oscap_report_parser_get_findings(monkeypatch, caplog):
    oscap_report_parser = OscapReportParser()
    monkeypatch.setattr(ElementTree, "parse", lambda *args,**kwargs: None)
    oscap_report_parser.get_findings(MockPath("mockedpath"),("str","test"))

   
@pytest.fixture
def mock_rule_info():
    class MockFinding:
        text = "mock_text"
        attrib = {"href": "mock_href", "identifier": "mock_identifier"}

    class MockRuleInfo:
        findings = [MockFinding()]
        identifier = "identifier"
        severity = "severity"
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
        # namespaces: ClassVar[dict[str, str]] = {
        #     "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        #     "dc": "http://purl.org/dc/elements/1.1/",
        #     "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        # }
        # oval_rule: ClassVar[
        #     str
        # ] = "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"
        # pass_results: ClassVar[tuple[str]] = ("pass", "notapplicable")
        # skip_results: ClassVar[tuple[str]] = "notselected"
        # fail_results: ClassVar[tuple[str]] = ("notchecked", "fail", "error")
        oval_name: str = ""
        oval_href: str = ""


    return MockRuleInfo()

def test_get_findings_from_rule_info(mock_rule_info, monkeypatch, caplog):
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: None)

    with caplog.at_level(logging.DEBUG):
        findings = list(OscapOVALFinding.get_findings_from_rule_info(mock_rule_info))

    assert len(findings) == 1

    OscapOVALFinding(
        identifier="mock_text",
        link="https://example.com",
        rule_id=None,
        severity = "severity"
    )
    # TODO: figure out the assert statement for this test
    # assert "Generating OVAL finding: mock_text" in caplog.text
    # assert caplog.records[0].message == "Generating OVAL finding: mock_text"

@pytest.fixture
def mock_rule_info():
    mock_obj = mock.Mock()
    mock_obj.rule_id = "12345"
    mock_obj.title = "Mock Rule Title"
    mock_obj.severity = "medium"
    return mock_obj


def test_oscap_compliance_finding(mock_rule_info, caplog):
    finding = OscapComplianceFinding(
        rule_id="12345",
        title="Mock Rule Title",
        severity="medium",
        identifier="identifier"
    )
    assert finding.rule_id == "12345"
    assert finding.title == "Mock Rule Title"
    assert finding.severity == "medium"
    
    caplog.clear()
    with caplog.at_level("DEBUG"):
        findings = list(OscapComplianceFinding.get_findings_from_rule_info(mock_rule_info))
        assert len(findings) == 1
        assert findings[0].rule_id == "12345"
        assert findings[0].title == "Mock Rule Title"
        assert findings[0].severity == "medium"

# OscapFinding
# RuleInfoOVAL
# RuleInfo