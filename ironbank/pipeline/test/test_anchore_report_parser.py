import inspect
import pytest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.scan_report_parsers.anchore import (
    AnchoreSecurityParser,
    AnchoreVuln,
)

log = logger.setup(name="anchore_report_parser")


@pytest.fixture
def mock_vuln_data():
    return {
        "tag": "registry.example/mock/test:1.0",
        "vuln": "CVE-123-ABC",
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
def mock_vulns(mock_vuln_data):
    return {"vulnerabilities": [mock_vuln_data], "imageFullTag": "mock_full_tag"}


# used for all method testing except __post_init__ (need to mock post init functionality to prevent unexpected state change after initialization)
class MockAnchoreVuln(AnchoreVuln):
    def __post_init__(self):
        # add vuln to mock expected data
        self.identifiers.append(self.vuln)


# used for testing __post_init__ (mock all methods used by __post_init__)
class MAVPostInitPatches(AnchoreVuln):
    def sort_fix(self):
        self.fix = "sorted_fix"

    def get_nvd_scores(self, ver):
        setattr(self, f"nvd_cvss_{ver}_vector", "mock_nvd_score")

    def get_vendor_nvd_scores(self, ver):
        setattr(self, f"vendor_cvss_{ver}_vector", "mock_vendor_score")

    def get_identifiers(self):
        setattr(self, "identifiers", [*self.identifiers, "CVE-456-DEF"])


@pytest.fixture
def mock_anchore_vuln(mock_vuln_data):
    return MockAnchoreVuln(**mock_vuln_data)


def test_anchore_vuln_post_init(mock_vuln_data):
    log.info("Validate post init")
    mav = MAVPostInitPatches(**mock_vuln_data)
    assert mav.fix == "sorted_fix"
    assert mav.description == "new_description"
    assert mav.identifiers == [mav.vuln, "CVE-456-DEF"]
    assert mav.nvd_cvss_v2_vector == "mock_nvd_score"
    assert mav.nvd_cvss_v3_vector == "mock_nvd_score"
    assert mav.vendor_cvss_v2_vector == "mock_vendor_score"
    assert mav.vendor_cvss_v3_vector == "mock_vendor_score"


def test_anchore_vuln_properties(mock_anchore_vuln):
    log.info("Validate properties")
    assert mock_anchore_vuln.inherited == mock_anchore_vuln.inherited_from_base
    assert mock_anchore_vuln.finding == mock_anchore_vuln.vuln
    assert mock_anchore_vuln.cve == mock_anchore_vuln.vuln
    assert mock_anchore_vuln.packagePath == mock_anchore_vuln.package_path
    assert mock_anchore_vuln.scanSource == mock_anchore_vuln.scan_source
    assert mock_anchore_vuln.link == mock_anchore_vuln.url


def test_from_dict(mock_anchore_vuln, mock_vuln_data):
    log.info("Test initializing class from dictionary with additional keys")
    mock_vuln_data_extra_vals = {
        **mock_vuln_data,
        "mock": "data",
        "additional": "value",
    }
    assert mock_anchore_vuln.from_dict(mock_vuln_data_extra_vals) == mock_anchore_vuln


def test_get_nvd_score(mock_anchore_vuln):
    log.info("Test nvd score is set correctly")
    mock_anchore_vuln.get_nvd_scores("v2")
    assert mock_anchore_vuln.nvd_cvss_v2_vector == "mock_nvd_vector"
    mock_anchore_vuln.get_nvd_scores("v3")
    assert mock_anchore_vuln.nvd_cvss_v3_vector is None


def test_get_vendor_score(mock_anchore_vuln):
    log.info("Test vendor score is set correctly")
    mock_anchore_vuln.get_vendor_nvd_scores("v2")
    assert mock_anchore_vuln.vendor_cvss_v2_vector == "mock_vendor_vector"
    mock_anchore_vuln.get_vendor_nvd_scores("v3")
    assert mock_anchore_vuln.vendor_cvss_v3_vector is None


def test_get_identifiers(mock_vuln_data):
    mock_new_vuln_id = "CVE-EXAMPLE-111"
    log.info("Test no nvd data available")
    mock_anchore_vuln_ident = MockAnchoreVuln(**mock_vuln_data)
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [mock_anchore_vuln_ident.vuln]

    log.info("Test no nvd data and vendor data includes existing cve")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "vendor_data": [{"id": mock_vuln_data["vuln"]}]}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [mock_anchore_vuln_ident.vuln]

    log.info("Test no nvd data available and vendor data produces new vuln id")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "vendor_data": [{"id": mock_new_vuln_id}]}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
        mock_new_vuln_id,
    ]

    # TODO: consider looping through these checks to remove duplicate code
    log.info("Test nvd data is available, is not a list, and includes existing cve")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "nvd_data": {"id": mock_vuln_data["vuln"]}}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
    ]

    log.info("Test nvd data is available, is not a list, and includes new cve")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "nvd_data": {"id": mock_new_vuln_id}}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
        mock_new_vuln_id,
    ]

    log.info("Test nvd data is available, is a list, and includes existing cve")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "nvd_data": [{"id": mock_vuln_data["vuln"]}]}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
    ]

    log.info("Test nvd data is available, is a list, and includes new cve")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "nvd_data": [{"id": mock_new_vuln_id}]}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
        mock_new_vuln_id,
    ]


def test_get_truncated_url(caplog, mock_anchore_vuln, mock_vuln_data):
    log.info("Test url is not a list")
    prior_url = mock_anchore_vuln.url
    mock_anchore_vuln.get_truncated_url()
    assert mock_anchore_vuln.url == prior_url

    mock_urls = [{"source": f"{i}", "url": f"{i}"} for i in range(50)]
    expected_iterations = lambda x: "".join(  # noqa E731
        [f"{i}:{i}\n" for i in range(x)]
    )

    log.info("Test url is a list and url will not be truncated")
    mock_anchore_vuln_short_url = MockAnchoreVuln(
        **{**mock_vuln_data, "url": mock_urls}
    )
    mock_anchore_vuln_short_url.get_truncated_url()
    assert mock_anchore_vuln_short_url.url == expected_iterations(50)

    log.info("Test url is a list and url will be truncated")
    mock_anchore_vuln_short_url = MockAnchoreVuln(
        **{**mock_vuln_data, "url": mock_urls}
    )
    mock_anchore_vuln_short_url.get_truncated_url(5)
    assert mock_anchore_vuln_short_url.url == expected_iterations(1)
    assert "Unable to add all reference URLs to API POST" in caplog.text


def test_sort_fix(mock_vuln_data):
    log.info("Test sort is successful")
    mock_fix_versions = f"{mock_vuln_data['fix']},5.0.0,1.2.3,4.5.1,2.0.3"
    mock_anchore_vuln_fix = MockAnchoreVuln(
        **{**mock_vuln_data, "fix": mock_fix_versions}
    )
    mock_anchore_vuln_fix.sort_fix()
    assert mock_anchore_vuln_fix.fix == ", ".join(sorted(mock_fix_versions.split(",")))


def test_dict(mock_anchore_vuln):
    log.info("Test dict returns expected keys/values")
    # filter out user-defined methods and built-in functions
    mock_anchore_vuln_attrs = inspect.getmembers(
        mock_anchore_vuln, lambda x: not inspect.isroutine(x)
    )
    # filter out magic methods
    mock_anchore_vuln_attrs = [
        attr[0] for attr in mock_anchore_vuln_attrs if (not attr[0].endswith("__"))
    ]
    mock_anchore_vuln_dict = mock_anchore_vuln.dict()
    assert sorted(mock_anchore_vuln_attrs) == sorted(
        list(mock_anchore_vuln_dict.keys())
    )


def test_get_vulnerabilities(monkeypatch, mock_vulns):
    log.info("Test vulnerabilites are parsed from scan report")
    mock_anchore_security_parser = AnchoreSecurityParser()
    monkeypatch.setattr(AnchoreVuln, "from_dict", lambda vuln_data: vuln_data)
    vulns = mock_anchore_security_parser.get_vulnerabilities(mock_vulns)
    assert vulns == [
        {**mock_vulns["vulnerabilities"][0], "tag": mock_vulns["imageFullTag"]}
    ]