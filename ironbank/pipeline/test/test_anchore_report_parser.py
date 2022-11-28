import pytest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.scan_report_parsers.anchore import (
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
        "fix": "example_fix",
        "url": "https://pypi.example/mock_package",
        "extra": {
            "description": "new_description",
            "example": "data",
            "nvd_data": [{"cvss_v2": {"vector_string": "mock_nvd_vector"}}],
            "vendor_data": [{"cvss_v2": {"vector_string": "mock_vendor_vector"}}],
        },
    }


class MockAnchoreVuln(AnchoreVuln):
    def __post_init__(self):
        # add vuln to mock expected data
        self.identifiers.append(self.vuln)


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


@pytest.mark.only
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


@pytest.mark.only
def test_anchore_vuln_properties(mock_anchore_vuln):
    log.info("Validate properties")
    assert mock_anchore_vuln.inherited == mock_anchore_vuln.inherited_from_base
    assert mock_anchore_vuln.finding == mock_anchore_vuln.vuln
    assert mock_anchore_vuln.cve == mock_anchore_vuln.vuln
    assert mock_anchore_vuln.packagePath == mock_anchore_vuln.package_path
    assert mock_anchore_vuln.scanSource == mock_anchore_vuln.scan_source
    assert mock_anchore_vuln.link == mock_anchore_vuln.url


@pytest.mark.only
def test_from_dict(mock_anchore_vuln, mock_vuln_data):
    log.info("Test initializing class from dictionary with additional keys")
    mock_vuln_data_extra_vals = {
        **mock_vuln_data,
        "mock": "data",
        "additional": "value",
    }
    assert mock_anchore_vuln.from_dict(mock_vuln_data_extra_vals) == mock_anchore_vuln


@pytest.mark.only
def test_get_nvd_score(mock_anchore_vuln):
    log.info("Test nvd score is set correctly")
    mock_anchore_vuln.get_nvd_scores("v2")
    assert mock_anchore_vuln.nvd_cvss_v2_vector == "mock_nvd_vector"
    assert mock_anchore_vuln.nvd_cvss_v3_vector is None


@pytest.mark.only
def test_get_vendor_score(mock_anchore_vuln):
    log.info("Test vendor score is set correctly")
    mock_anchore_vuln.get_vendor_nvd_scores("v2")
    assert mock_anchore_vuln.vendor_cvss_v2_vector == "mock_vendor_vector"
    assert mock_anchore_vuln.vendor_cvss_v3_vector is None


@pytest.mark.only
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

    log.info("test no nvd data available and vendor data produces new vuln id")
    mock_anchore_vuln_ident = MockAnchoreVuln(
        **{**mock_vuln_data, "vendor_data": [{"id": mock_new_vuln_id}]}
    )
    mock_anchore_vuln_ident.get_identifiers()
    assert mock_anchore_vuln_ident.identifiers == [
        mock_anchore_vuln_ident.vuln,
        mock_new_vuln_id,
    ]
