import json

import pytest

from ironbank.pipeline.scan_report_parsers.anchore import (
    AnchoreCVEFinding,
    AnchoreReportParser,
)
from ironbank.pipeline.test.mocks.mock_classes import MockPath, TestUtils
from ironbank.pipeline.utils import logger

log = logger.setup(name="anchore_report_parser")


@pytest.fixture
def mock_finding_data():
    return {
        "tag": "registry.example/mock/test:1.0",
        "identifier": "CVE-123-ABC",
        "severity": "High",
        "feed": "mock_feed",
        "feed_group": "mock_feed_group",
        "package": "mock_package",
        "package_path": "/usr/local/bin/mock_package",
        "package_type": "python",
        "package_version": "1.0",
        "fix": "1.0.0",
        "url": "https://pypi.example/mock_package",
        "extra": {
            "description": "new_description",
            "example": "data",
            "nvd_data": [{"cvss_v2": {"vector_string": "mock_nvd_vector"}}],
            "vendor_data": [{"cvss_v2": {"vector_string": "mock_vendor_vector"}}],
        },
    }


@pytest.fixture
def mock_findings_data(mock_finding_data):
    return {"vulnerabilities": [mock_finding_data], "imageFullTag": "mock_full_tag"}


# used for all method testing except __post_init__ (need to mock post init functionality to prevent unexpected state change after initialization)
class MockAnchoreCVEFinding(AnchoreCVEFinding):
    def __post_init__(self):
        # add vuln to mock expected data
        self.identifiers.append(self.vuln)


# used for testing __post_init__ (mock all methods used by __post_init__)
class MockAnchoreCVEPatched(AnchoreCVEFinding):
    def set_sorted_fix(self):
        self.fix = "sorted_fix"

    def set_nvd_scores(self, ver):
        setattr(self, f"nvd_cvss_{ver}_vector", "mock_nvd_score")

    def set_vendor_nvd_scores(self, ver):
        setattr(self, f"vendor_cvss_{ver}_vector", "mock_vendor_score")

    def set_identifiers(self):
        setattr(self, "identifiers", [*self.identifiers, "CVE-456-DEF"])


@pytest.fixture
def mock_anchore_finding(mock_finding_data):
    return MockAnchoreCVEFinding(**mock_finding_data)


def test_anchore_vuln_post_init(mock_finding_data):
    log.info("Validate post init")
    mav = MockAnchoreCVEPatched(**mock_finding_data)
    assert mav.fix == "sorted_fix"
    assert mav.description == "new_description"
    assert mav.identifiers == [mav.vuln, "CVE-456-DEF"]
    assert mav.nvd_cvss_v2_vector == "mock_nvd_score"
    assert mav.nvd_cvss_v3_vector == "mock_nvd_score"
    assert mav.vendor_cvss_v2_vector == "mock_vendor_score"
    assert mav.vendor_cvss_v3_vector == "mock_vendor_score"


def test_anchore_vuln_properties(mock_anchore_finding):
    log.info("Validate properties")
    assert mock_anchore_finding.inherited == mock_anchore_finding.inherited_from_base
    assert mock_anchore_finding.finding == mock_anchore_finding.vuln
    assert mock_anchore_finding.cve == mock_anchore_finding.vuln
    assert mock_anchore_finding.packagePath == mock_anchore_finding.package_path
    assert mock_anchore_finding.scanSource == mock_anchore_finding.scan_source
    assert mock_anchore_finding.link == mock_anchore_finding.url


def test_from_dict(mock_anchore_finding, mock_finding_data):
    log.info("Test initializing class from dictionary with additional keys")
    mock_finding_data_extra_vals = {
        **mock_finding_data,
        "mock": "data",
        "additional": "value",
    }
    assert (
        mock_anchore_finding.from_dict(mock_finding_data_extra_vals)
        == mock_anchore_finding
    )


def test_get_nvd_score(mock_anchore_finding):
    log.info("Test nvd score is set correctly")
    mock_anchore_finding.set_nvd_scores("v2")
    assert mock_anchore_finding.nvd_cvss_v2_vector == "mock_nvd_vector"
    mock_anchore_finding.set_nvd_scores("v3")
    assert mock_anchore_finding.nvd_cvss_v3_vector is None


def test_get_vendor_score(mock_anchore_finding):
    log.info("Test vendor score is set correctly")
    mock_anchore_finding.set_vendor_nvd_scores("v2")
    assert mock_anchore_finding.vendor_cvss_v2_vector == "mock_vendor_vector"
    mock_anchore_finding.set_vendor_nvd_scores("v3")
    assert mock_anchore_finding.vendor_cvss_v3_vector is None


def test_get_identifiers(mock_finding_data):
    mock_new_vuln_id = "CVE-EXAMPLE-111"
    log.info("Test no nvd data available")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(**mock_finding_data)
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [mock_anchore_finding_ident.vuln]

    log.info("Test no nvd data and vendor data includes existing cve")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{
            **mock_finding_data,
            "vendor_data": [{"id": mock_finding_data["identifier"]}],
        }
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [mock_anchore_finding_ident.vuln]

    log.info("Test no nvd data available and vendor data produces new vuln id")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{**mock_finding_data, "vendor_data": [{"id": mock_new_vuln_id}]}
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [
        mock_anchore_finding_ident.vuln,
        mock_new_vuln_id,
    ]

    # TODO: consider looping through these checks to remove duplicate code
    log.info("Test nvd data is available, is not a list, and includes existing cve")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{**mock_finding_data, "nvd_data": {"id": mock_finding_data["identifier"]}}
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [
        mock_anchore_finding_ident.vuln,
    ]

    log.info("Test nvd data is available, is not a list, and includes new cve")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{**mock_finding_data, "nvd_data": {"id": mock_new_vuln_id}}
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [
        mock_anchore_finding_ident.vuln,
        mock_new_vuln_id,
    ]

    log.info("Test nvd data is available, is a list, and includes existing cve")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{**mock_finding_data, "nvd_data": [{"id": mock_finding_data["identifier"]}]}
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [
        mock_anchore_finding_ident.vuln,
    ]

    log.info("Test nvd data is available, is a list, and includes new cve")
    mock_anchore_finding_ident = MockAnchoreCVEFinding(
        **{**mock_finding_data, "nvd_data": [{"id": mock_new_vuln_id}]}
    )
    mock_anchore_finding_ident.set_identifiers()
    assert mock_anchore_finding_ident.identifiers == [
        mock_anchore_finding_ident.vuln,
        mock_new_vuln_id,
    ]


def test_get_truncated_url(caplog, mock_anchore_finding, mock_finding_data):
    log.info("Test url is not a list")
    prior_url = mock_anchore_finding.url
    mock_anchore_finding.set_truncated_url()
    assert mock_anchore_finding.url == prior_url

    mock_urls = [{"source": f"{i}", "url": f"{i}"} for i in range(50)]

    def expected_iterations(iterations):
        return "".join([f"{i}:{i}\n" for i in range(iterations)])

    log.info("Test url is a list and url will not be truncated")
    mock_anchore_finding_short_url = MockAnchoreCVEFinding(
        **{**mock_finding_data, "url": mock_urls}
    )
    mock_anchore_finding_short_url.set_truncated_url()
    assert mock_anchore_finding_short_url.url == expected_iterations(50)

    log.info("Test url is a list and url will be truncated")
    mock_anchore_finding_short_url = MockAnchoreCVEFinding(
        **{**mock_finding_data, "url": mock_urls}
    )
    mock_anchore_finding_short_url.set_truncated_url(5)
    assert mock_anchore_finding_short_url.url == expected_iterations(1)
    assert "Unable to add all reference URLs to API POST" in caplog.text


def test_sort_fix(mock_finding_data):
    log.info("Test sort is successful")
    mock_fix_versions = f"{mock_finding_data['fix']},5.0.0,1.2.3,4.5.1,2.0.3"
    mock_anchore_finding_fix = MockAnchoreCVEFinding(
        **{**mock_finding_data, "fix": mock_fix_versions}
    )
    mock_anchore_finding_fix.set_sorted_fix()
    assert mock_anchore_finding_fix.fix == ", ".join(
        sorted(mock_fix_versions.split(","))
    )


def test_dict(mock_anchore_finding):
    log.info("Test dict returns expected keys/values")

    mock_anchore_finding_dict = mock_anchore_finding.as_dict()
    mock_anchore_finding_attrs = TestUtils.get_attrs_from_object(mock_anchore_finding)
    assert sorted(mock_anchore_finding_attrs) == sorted(
        list(mock_anchore_finding_dict.keys())
    )


def test_get_findings(monkeypatch, mock_findings_data):
    log.info("Test vulnerabilites are parsed from scan report")
    mock_anchore_security_parser = AnchoreReportParser()
    monkeypatch.setattr(AnchoreCVEFinding, "from_dict", lambda vuln_data: vuln_data)
    monkeypatch.setattr(json, "loads", lambda x: x)
    mock_findings_data["vulnerabilities"][0]["vuln"] = mock_findings_data[
        "vulnerabilities"
    ][0]["identifier"]
    vulns = mock_anchore_security_parser.get_findings(
        MockPath(".", mock_data=mock_findings_data)
    )
    assert vulns == [
        {
            **mock_findings_data["vulnerabilities"][0],
            "tag": mock_findings_data["imageFullTag"],
        }
    ]
