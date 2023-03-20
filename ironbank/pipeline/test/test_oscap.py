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
def rule_info_mocker(monkeypatch, mock_element_tree, mock_element):
    def base():
        return MockRuleInfo(root=mock_element_tree, rule_result=mock_element)

    def oval():
        return MockRuleInfo(
            root=mock_element_tree, rule_result=MockElement(fake_type="OVAL")
        )

    def with_base_method(method_name):
        # using __dict__ to get a function object back instead of a method object
        # using getattr will point to the RuleInfo's method, which would cause any other classmethods to be pulled from the RuleInfo class instead of the MockRuleInfo
        # i.e. using getattr would return method object which would cause classmethods to have undesired behavior
        monkeypatch.setattr(MockRuleInfo, method_name, RuleInfo.__dict__[method_name])
        return base()

    def with_oval_method(method_name):
        # refer to comment in with_base_method above
        monkeypatch.setattr(
            MockRuleInfoOVAL, method_name, RuleInfoOVAL.__dict__[method_name]
        )
        return oval()

    return {
        "base": base,
        "oval": oval,
        # provide versions of mocked class with real definition
        # k:v example: "with_set_identifiers": MockRuleInfo() with set_identifiers unmocked
        "base_with_method": with_base_method,
        "oval_with_method": with_oval_method,
    }


@pytest.fixture
def mock_text():
    return "mock text"


def test_oscap_get_default_init_params(rule_info_mocker):
    log.info("Test retrieving all default init params for OscapFinding object")

    default_params = OscapFinding.get_default_init_params(rule_info_mocker["base"]())
    assert default_params


@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapComplianceFinding",
    new=MockOscapComplianceFinding,
)
@patch(
    "ironbank.pipeline.scan_report_parsers.oscap.OscapOVALFinding",
    new=MockOscapOVALFinding,
)
def test_oscap_get_findings_from_rule_info(rule_info_mocker):
    assert (
        OscapFinding.get_findings_from_rule_info(rule_info_mocker["base"]())
        == MockOscapComplianceFinding
    )
    assert (
        OscapFinding.get_findings_from_rule_info(rule_info_mocker["oval"]())
        == MockOscapOVALFinding
    )


def test_as_dict(mock_oscap_finding):
    log.info("Test all attributes are included in as_dict")
    mock_oscap_finding_attrs = TestUtils.get_attrs_from_object(mock_oscap_finding)
    mock_oscap_finding_dict = mock_oscap_finding.as_dict()
    assert sorted(mock_oscap_finding_attrs) == sorted(
        list(mock_oscap_finding_dict.keys())
    )


def test_oscap_oval_get_findings_from_rule_info(mock_text, rule_info_mocker):
    findings_from_rule_info = list(
        OscapOVALFinding.get_findings_from_rule_info(rule_info_mocker["oval"]())
    )
    assert isinstance(findings_from_rule_info[0], OscapOVALFinding)
    assert findings_from_rule_info[0].link is not None
    assert findings_from_rule_info[0].identifier == mock_text


def test_oscap_compliance_get_findings_from_rule_info(rule_info_mocker):
    mock_rule_info = rule_info_mocker["base"]()
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


def test_rule_info_init(monkeypatch, mock_element_tree, mock_element):
    log.info("Test constructor gets base rule info and inits correctly")
    monkeypatch.setattr(MockRuleInfo, "__new__", RuleInfo.__new__)
    monkeypatch.setattr(MockRuleInfo, "__post_init__", RuleInfo.__post_init__)
    # we have to do this a `with patch` instead of using the decorator so the mocks we're doing before this line apply
    with patch("ironbank.pipeline.scan_report_parsers.oscap.RuleInfo", MockRuleInfo):
        rule_info = MockRuleInfo(root=mock_element_tree, rule_result=mock_element)
        assert isinstance(rule_info, RuleInfo)


def test_rule_info_format_reference(monkeypatch, mock_element, rule_info_mocker):
    log.info("Test formatting a reference element")
    mock_rule_info = rule_info_mocker["base_with_method"]("_format_reference")
    reference = mock_rule_info._format_reference(mock_element)
    # title and identifier are pulled from the params passed to `.find`
    assert ":title" in reference
    assert ":identifier" in reference
    log.info("Test skipping formatting a reference")
    monkeypatch.setattr(MockElement, "find", lambda *args, **kwargs: None)
    reference = mock_rule_info._format_reference(mock_element)
    assert reference == mock_element.text


def test_rule_info_set_identifiers(mock_element, rule_info_mocker):
    log.info("Test setting identifiers from rule object")
    mock_rule_info = rule_info_mocker["base_with_method"]("set_identifiers")
    mock_rule_info.set_identifiers(mock_element)
    assert ":ident" in mock_rule_info.identifiers[0]
    assert ":ident" in mock_rule_info.identifier


def test_rule_info_get_result(mock_element, rule_info_mocker):
    log.info("Test getting result from rule result")
    result = rule_info_mocker["base_with_method"]("get_result").get_result(mock_element)
    assert ":result" in result


def test_rule_info_set_result(mock_element, rule_info_mocker):
    log.info("Test setting result from rule result")
    mock_rule_info = rule_info_mocker["base_with_method"]("set_result")
    mock_rule_info.set_result(mock_element)
    assert "mock_result" in mock_rule_info.result


def test_rule_info_set_description(monkeypatch, mock_element, rule_info_mocker):
    log.info("Test setting description from rule")
    mock_rule_info = rule_info_mocker["base_with_method"]("set_description")
    monkeypatch.setattr(
        ElementTree, "tostring", lambda x, method: x.text.encode("utf-8")
    )
    mock_rule_info.set_description(mock_element)
    assert ":description" in mock_rule_info.description


def test_rule_info_set_references(mock_element, rule_info_mocker):
    log.info("Test setting references from rule")
    mock_rule_info = rule_info_mocker["base_with_method"]("set_references")
    mock_rule_info.set_references(mock_element)
    assert "mock_formatted_reference" in mock_rule_info.references


def test_rule_info_get_results(monkeypatch, mock_element, rule_info_mocker):
    log.info("Test get results with filter")
    mock_rule_info = rule_info_mocker["base_with_method"]("get_results")
    assert mock_rule_info.get_results(mock_element, ["mock_result"]) != []

    log.info("Test get results without filter")
    assert mock_rule_info.get_results(mock_element, None) != []

    log.info("Test get results with no filter match")
    assert mock_rule_info.get_results(mock_element, ["no_match"]) == []

    log.info("Test skip result")
    monkeypatch.setattr(MockRuleInfo, "get_result", lambda x: RuleInfo.skip_results[0])
    assert mock_rule_info.get_results(mock_element, None) == []


def test_rule_info_oval_init(monkeypatch, caplog, mock_element_tree, mock_element):
    log.info("Test constructing RuleInfoOVAL directly")
    monkeypatch.setattr(MockRuleInfoOVAL, "__new__", RuleInfoOVAL.__new__)
    rule_info_oval = MockRuleInfoOVAL(
        root=mock_element_tree,
        rule_result=mock_element,
        rule_id=RuleInfo.oval_rule,
    )
    assert "Constructing RuleInfoOVAL directly" in caplog.text
    caplog.clear()

    log.info("Test instantiating a RuleInfoOVAL object")
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


def test_rule_info_oval_set_oval_val_from_ref(mock_element, rule_info_mocker):
    log.info("Test setting oval vals from xml element")
    mock_rule_info = rule_info_mocker["oval_with_method"]("set_oval_val_from_ref")
    mock_rule_info.set_oval_val_from_ref("href", mock_element)
    assert mock_rule_info.oval_href == "mock_href"


def test_rule_info_oval_set_oval_name(
    monkeypatch, caplog, mock_element, rule_info_mocker
):
    log.info("Test setting oval name attribute")
    mock_rule_info = rule_info_mocker["oval_with_method"]("set_oval_name")
    mock_rule_info.set_oval_name(mock_element)
    assert "mock_name set for name" in caplog.text
