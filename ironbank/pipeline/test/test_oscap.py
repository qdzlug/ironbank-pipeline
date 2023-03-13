#!/usr/bin/env python3


from dataclasses import dataclass
import random
import unittest
from xml.etree import ElementTree
from ironbank.pipeline.scan_report_parsers.oscap import (
    OscapReportParser,
    OscapFinding,
    OscapOVALFinding,
    RuleInfo,
    OscapComplianceFinding,
    RuleInfoOVAL,
)
from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser
from ironbank.pipeline.test.mocks.mock_classes import MockPath
import pytest
from unittest.mock import patch
from xml.etree.ElementTree import ElementTree, Element
from typing import Callable, Generator
import logging
import pytest
import ironbank

from unittest import mock
from pathlib import Path
from ironbank.pipeline.utils import logger
from dataclasses import InitVar, dataclass, field

log = logger.setup("test_oscap")


@dataclass
class MockOscapComplianceFinding(OscapComplianceFinding):
    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return cls

@dataclass
class MockOscapOVALFinding(OscapOVALFinding):
    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return cls

@dataclass
class MockOscapFinding(OscapFinding):
    identifier: str = ""
    severity: str = ""
    identifiers: tuple = field(default_factory=lambda: ())

    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return [
            MockOscapComplianceFinding(
                identifier=rule_info.identifier, rule_id="rule1", severity=""
            ),
        ]


@dataclass
class MockElement:
    text: str = "mock text"
    attrib: dict = field(
        default_factory=lambda: {"idref": "example_id", "href": "href"}
    )
    fake_type: str = "compliance"


@dataclass
class MockElementTree:
    def find():
        pass

    def findall():
        pass


# @pytest.fixture
# def mock_element():
#     return {
#         "short_rule_id": MockElement(''),
#         "default": MockElement()
#     }


@dataclass
class MockRuleInfo(RuleInfo):
    rule_id: str = "12345"
    title: str = "Mock Rule Title"
    severity: str = "medium"

    def __new__(
        cls, root: MockElementTree, rule_result: MockElement
    ) -> Callable:  # pylint: disable=unused-argument
        return object.__new__(
            MockRuleInfoOval if (rule_result.fake_type == "OVAL") else MockRuleInfo
        )

    def __post_init__(self, root: ElementTree, rule_result: Element):
        self.identifier = str(random.randint(0, 1000))

    def get_results(self, results_filter: list[str]):
        return [
            MockElement(text="abc"),
            MockElement(text="def"),
            MockElement(text="ghi"),
        ]


@dataclass
class MockRuleInfoOval(MockRuleInfo, RuleInfoOVAL):
    findings: list[MockElement] = field(default_factory=lambda: [MockElement()])


@dataclass
class MockReportParser(ReportParser):
    @classmethod
    def dedupe_findings_by_attr(
        cls, findings: list[MockOscapFinding], attribute: str
    ) -> list[MockOscapFinding]:
        log.error("TEST TEST TEST")
        return findings

def test_oscap_get_default_init_params():
    mock_text = "mock text"
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(), rule_result=MockElement(text=mock_text)
    )
    default_params = OscapFinding.get_default_init_params(mock_rule_info)

@patch("ironbank.pipeline.scan_report_parsers.oscap.OscapComplianceFinding", new=MockOscapComplianceFinding)
@patch("ironbank.pipeline.scan_report_parsers.oscap.OscapOVALFinding", new=MockOscapOVALFinding)
def test_oscap_get_findings_from_rule_info(monkeypatch):
    mock_text = "mock text"
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(),
        rule_result=MockElement(text=mock_text),
    )
    assert OscapFinding.get_findings_from_rule_info(mock_rule_info) == MockOscapComplianceFinding
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(),
        rule_result=MockElement(fake_type="OVAL", text=mock_text),
    )
    assert OscapFinding.get_findings_from_rule_info(mock_rule_info) == MockOscapOVALFinding

def test_oscap_oval_get_findings_from_rule_info(monkeypatch, caplog):
    mock_text = "mock text"
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(),
        rule_result=MockElement(fake_type="OVAL", text=mock_text),
    )
    findings_from_rule_info = list(
        OscapOVALFinding.get_findings_from_rule_info(mock_rule_info)
    )

    assert isinstance(findings_from_rule_info[0], OscapOVALFinding)
    assert findings_from_rule_info[0].link is not None
    assert findings_from_rule_info[0].identifier == mock_text


def test_oscap_compliance_get_findings_from_rule_info(monkeypatch, caplog):
    mock_text = "mock text"
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(), rule_result=MockElement(text=mock_text)
    )
    findings_from_rule_info = list(
        OscapComplianceFinding.get_findings_from_rule_info(mock_rule_info)
    )

    assert isinstance(findings_from_rule_info[0], OscapComplianceFinding)
    assert getattr(findings_from_rule_info[0], "link", None) is None
    assert findings_from_rule_info[0].identifier == mock_rule_info.identifier


@pytest.mark.only
@patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", new=MockRuleInfo)
@patch("ironbank.pipeline.scan_report_parsers.oscap.OscapFinding", new=MockOscapFinding)
def test_oscap_report_parser_get_findings(monkeypatch, caplog):
    oscap_report_parser = OscapReportParser()
    monkeypatch.setattr(ElementTree, "parse", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        ironbank.pipeline.scan_report_parsers.oscap, "flatten", lambda x: x
    )
    monkeypatch.setattr(
        ironbank.pipeline.scan_report_parsers.oscap.OscapReportParser,
        "dedupe_findings_by_attr",
        MockReportParser.dedupe_findings_by_attr,
    )
    oscap_report_parser.get_findings(MockPath("mockedpath"), ("str", "test"))

def test_as_dict():
    oscap_finding = OscapFinding(identifier="name", severity="Hello")
    oscap_finding.as_dict()






# def test_get_findings_from_rule_info(self):
#     findings = OscapFinding.get_findings_from_rule_info(self.rule_info)
#     self.assertIsInstance(findings, Generator)

# def test_desc_property(self):
#     finding = OscapFinding(description="This is a finding.")
#     self.assertEqual(finding.desc, "This is a finding.")

# def test_refs_property(self):
#     finding = OscapFinding(references="https://example.com/")
#     self.assertEqual(finding.refs, "https://example.com/")

# def test_ruleid_property(self):
#     finding = OscapFinding(rule_id="com.example.rule-123")
#     self.assertEqual(finding.ruleid, "com.example.rule-123")

# def test_as_dict_method(self):
#     finding = OscapFinding(
#         identifier="rule-123",
#         severity="high",
#         rule_id="com.example.rule-123",
#         title="Example Rule",
#         scanned_date="2022-01-01T00:00:00Z",
#         result="fail",
#         description="This is an example rule.",
#         references="https://example.com/",
#         rationale="This rule checks for compliance with security best practices."
#     )
#     expected_dict = {
#         "identifier": "rule-123",
#         "severity": "high",
#         "rule_id": "com.example.rule-123",
#         "title": "Example Rule",
#         "scanned_date": "2022-01-01T00:00:00Z",
#         "result": "fail",
#         "description": "This is an example rule.",
#         "refs": "https://example.com/",
#         "desc": "This is an example rule.",
#         "ruleid": "com.example.rule-123",
#     }
#     self.assertEqual(finding.as_dict(), expected_dict)


# RuleInfoOVAL
# RuleInfo
