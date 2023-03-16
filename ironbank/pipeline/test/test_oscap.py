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
def mock_element():
    return MockElement()


@pytest.fixture
def mock_element_tree():
    return MockElementTree()


@pytest.fixture
def mock_rule_info(monkeypatch, mock_element_tree, mock_element):
    def default_():
        return MockRuleInfo(root=mock_element_tree, rule_result=mock_element)

    def oval():
        return MockRuleInfo(
            root=mock_element_tree, rule_result=MockElement(fake_type="OVAL")
        )

    def with_method(method_name):
        monkeypatch.setattr(MockRuleInfo, method_name, getattr(RuleInfo, method_name))
        return default_()

    # TODO: use inspect to grab these from the class dynamically
    methods = [
        "_format_reference",
        "set_identifiers",
        "get_result",
        "set_result",
        "set_description",
        "set_references",
        "set_rationale",
        "get_rule_id",
        "get_results",
    ]

    return {
        "default": default_(),
        "oval": oval(),
        # provide versions of mocked class with real definition
        # k:v example: "with_set_identifiers": MockRuleInfo() with set_identifiers unmocked
        **{f"with_{m}": with_method(m) for m in methods},
    }


@pytest.fixture
def mock_text():
    return "mock text"


def test_oscap_get_default_init_params(mock_rule_info):
    log.info("Test retrieving all default init params for OscapFinding object")

    default_params = OscapFinding.get_default_init_params(mock_rule_info["default"])
    assert default_params


@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapComplianceFinding",
    new=MockOscapComplianceFinding,
)
@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapOVALFinding",
    new=MockOscapOVALFinding,
)
def test_oscap_get_findings_from_rule_info(mock_rule_info):
    assert (
        OscapFinding.get_findings_from_rule_info(mock_rule_info["default"])
        == MockOscapComplianceFinding
    )
    assert (
        OscapFinding.get_findings_from_rule_info(mock_rule_info["oval"])
        == MockOscapOVALFinding
    )


def test_as_dict(mock_oscap_finding):
    log.info("Test all attributes are included in as_dict")
    mock_oscap_finding_attrs = TestUtils.get_attrs_from_object(mock_oscap_finding)
    mock_oscap_finding_dict = mock_oscap_finding.as_dict()
    assert sorted(mock_oscap_finding_attrs) == sorted(
        list(mock_oscap_finding_dict.keys())
    )


def test_oscap_oval_get_findings_from_rule_info(mock_text, mock_rule_info):
    findings_from_rule_info = list(
        OscapOVALFinding.get_findings_from_rule_info(mock_rule_info["oval"])
    )
    assert isinstance(findings_from_rule_info[0], OscapOVALFinding)
    assert findings_from_rule_info[0].link is not None
    assert findings_from_rule_info[0].identifier == mock_text


def test_oscap_compliance_get_findings_from_rule_info(mock_rule_info):
    findings_from_rule_info = list(
        OscapComplianceFinding.get_findings_from_rule_info(mock_rule_info["default"])
    )

    assert isinstance(findings_from_rule_info[0], OscapComplianceFinding)
    assert getattr(findings_from_rule_info[0], "link", None) is None
    assert findings_from_rule_info[0].identifier == mock_rule_info["default"].identifier


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


def test_rule_info_init(monkeypatch, mock_element_tree, mock_element):
    log.info("Test constructor gets base rule info and inits correctly")
    monkeypatch.setattr(MockRuleInfo, "__new__", RuleInfo.__new__)
    monkeypatch.setattr(MockRuleInfo, "__post_init__", RuleInfo.__post_init__)
    # we have to do this a `with patch` instead of using the decorator so the mocks we're doing before this line apply
    with patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", MockRuleInfo):
        rule_info = MockRuleInfo(root=mock_element_tree, rule_result=mock_element)
        assert isinstance(rule_info, RuleInfo)


def test_rule_info_oval_init(monkeypatch, mock_element_tree, mock_element):
    monkeypatch.setattr(MockRuleInfo, "__new__", RuleInfo.__new__)
    monkeypatch.setattr(MockRuleInfoOVAL, "__post_init__", RuleInfoOVAL.__post_init__)
    monkeypatch.setattr(RuleInfo, "get_rule_id", lambda rule_obj: RuleInfo.oval_rule)
    with patch(
        "ironbank.pipeline.scan_report_parsers.oscap.RuleInfoOVAL", MockRuleInfoOVAL
    ):
        log.info("Test constructor gets oval rule info and inits correctly")

        monkeypatch.setattr(ElementTree, "parse", lambda *args, **kwargs: None)
        rule_info_oval = MockRuleInfo(
            root=mock_element_tree,
            rule_result=mock_element,
            rule_id=RuleInfo.oval_rule,
        )
        assert isinstance(rule_info_oval, RuleInfoOVAL)


def test_rule_info_format_reference(monkeypatch, mock_element, mock_rule_info):
    log.info("Test formatting a reference element")
    mock_rule_info = mock_rule_info["with__format_reference"]
    reference = mock_rule_info._format_reference(mock_element)
    # title and identifier are pulled from the params passed to `.find`
    assert ":title" in reference
    assert ":identifier" in reference
    log.info("Test skipping formatting a reference")
    monkeypatch.setattr(MockElement, "find", lambda *args, **kwargs: None)
    reference = mock_rule_info._format_reference(mock_element)
    assert reference == mock_element.text


def test_set_identifiers(mock_element, mock_rule_info):
    log.info("Test setting identifiers from rule object")
    mock_rule_info = mock_rule_info["with_set_identifiers"]
    mock_rule_info.set_identifiers(mock_element)
    assert ":ident" in mock_rule_info.identifiers[0]
    assert ":ident" in mock_rule_info.identifier


def test_get_result(mock_element, mock_rule_info):
    log.info("Test getting result from rule result")
    result = mock_rule_info["with_get_result"].get_result(mock_element)
    assert ":result" in result


def test_set_result(mock_element, mock_rule_info):
    log.info("Test setting result from rule result")
    mock_rule_info = mock_rule_info["with_set_result"]
    mock_rule_info.set_result(mock_element)
    assert ":result" in mock_rule_info.result


def test_set_description(monkeypatch, mock_element, mock_rule_info):
    log.info("Test setting description from rule")
    mock_rule_info = mock_rule_info["with_set_description"]
    monkeypatch.setattr(
        ElementTree, "tostring", lambda x, method: x.text.encode("utf-8")
    )
    mock_rule_info.set_description(mock_element)
    assert ":description" in mock_rule_info.description


def test_set_references():
    pass
