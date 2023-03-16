#!/usr/bin/env python3


from ironbank.pipeline.scan_report_parsers.oscap import (
    OscapReportParser,
    OscapFinding,
    OscapOVALFinding,
    RuleInfo,
    OscapComplianceFinding,
    RuleInfoOVAL,
)

from ironbank.pipeline.test.mocks.mock_classes import MockPath, TestUtils
import pytest
from unittest.mock import patch
from xml.etree import ElementTree
import ironbank

from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockRuleInfo,
    MockRuleInfoOVAL,
    MockElement,
    MockElementTree,
    MockOscapFinding,
    MockOscapComplianceFinding,
    MockOscapOVALFinding,
    MockReportParser,
)


log = logger.setup("test_oscap")


@pytest.fixture
def mock_oscap_finding():
    return MockOscapFinding()


@pytest.fixture
def mock_text():
    return "mock text"


def test_oscap_get_default_init_params(mock_text):
    log.info("Test retrieving all default init params for OscapFinding object")

    mock_rule_info = MockRuleInfo(
        root=MockElementTree(), rule_result=MockElement(text=mock_text)
    )
    default_params = OscapFinding.get_default_init_params(mock_rule_info)
    assert default_params


@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapComplianceFinding",
    new=MockOscapComplianceFinding,
)
@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapOVALFinding",
    new=MockOscapOVALFinding,
)
def test_oscap_get_findings_from_rule_info(mock_text):
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(),
        rule_result=MockElement(text=mock_text),
    )
    assert (
        OscapFinding.get_findings_from_rule_info(mock_rule_info)
        == MockOscapComplianceFinding
    )
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(),
        rule_result=MockElement(fake_type="OVAL", text=mock_text),
    )
    assert (
        OscapFinding.get_findings_from_rule_info(mock_rule_info) == MockOscapOVALFinding
    )


def test_as_dict(mock_oscap_finding):
    log.info("Test all attributes are included in as_dict")
    mock_oscap_finding_attrs = TestUtils.get_attrs_from_object(mock_oscap_finding)
    mock_oscap_finding_dict = mock_oscap_finding.as_dict()
    assert sorted(mock_oscap_finding_attrs) == sorted(
        list(mock_oscap_finding_dict.keys())
    )


def test_oscap_oval_get_findings_from_rule_info(mock_text):
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


def test_oscap_compliance_get_findings_from_rule_info(mock_text):
    mock_rule_info = MockRuleInfo(
        root=MockElementTree(), rule_result=MockElement(text=mock_text)
    )
    findings_from_rule_info = list(
        OscapComplianceFinding.get_findings_from_rule_info(mock_rule_info)
    )

    assert isinstance(findings_from_rule_info[0], OscapComplianceFinding)
    assert getattr(findings_from_rule_info[0], "link", None) is None
    assert findings_from_rule_info[0].identifier == mock_rule_info.identifier


@patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", new=MockRuleInfo)
@patch("ironbank.pipeline.scan_report_parsers.oscap.OscapFinding", new=MockOscapFinding)
def test_oscap_report_parser_get_findings(monkeypatch):
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


@pytest.mark.only
def test_rule_info_init(monkeypatch):
    log.info("Test constructor gets base rule info and inits correctly")
    monkeypatch.setattr(MockRuleInfo, "__new__", RuleInfo.__new__)
    monkeypatch.setattr(MockRuleInfo, "__post_init__", RuleInfo.__post_init__)
    monkeypatch.setattr(MockRuleInfo, "get_rule_id", lambda rule_obj: "12345")
    with patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", MockRuleInfo):
        mock_rule_info = MockRuleInfo(root=MockElementTree(), rule_result=MockElement())
        assert isinstance(mock_rule_info, RuleInfo)


@pytest.mark.only
def test_rule_info_oval_init(monkeypatch):
    monkeypatch.setattr(MockRuleInfo, "__new__", RuleInfo.__new__)
    monkeypatch.setattr(MockRuleInfoOVAL, "__post_init__", RuleInfoOVAL.__post_init__)
    monkeypatch.setattr(
        MockRuleInfo, "get_rule_id", lambda rule_obj: RuleInfo.oval_rule
    )
    with patch(
        "ironbank.pipeline.scan_report_parsers.oscap.RuleInfoOVAL", MockRuleInfoOVAL
    ):
        log.info("Test constructor gets oval rule info and inits correctly")

        monkeypatch.setattr(ElementTree, "parse", lambda *args, **kwargs: None)
        mock_rule_info = MockRuleInfo(
            root=MockElementTree(),
            rule_result=MockElement(),
            rule_id=RuleInfo.oval_rule,
        )
        assert isinstance(mock_rule_info, RuleInfoOVAL)
