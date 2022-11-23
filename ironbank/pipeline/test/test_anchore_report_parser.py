import pytest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.scan_report_parsers.anchore import (
    AnchoreSecurityParser,
    AnchoreVuln,
)

log = logger.setup(name="anchore_report_parser")


@pytest.fixture
def mock_anchore_vuln_args():
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
        "extra": {"description": "new_description", "example": "data"},
    }


@pytest.mark.only
def test_anchore_vuln_post_init(monkeypatch, mock_anchore_vuln_args):
    log.info("Validate post init")
    mock_extra_vuln = "CVE-456-DEF"
    monkeypatch.setattr(
        AnchoreVuln, "sort_fix", lambda self: setattr(self, "fix", "sorted_fix")
    )
    monkeypatch.setattr(
        AnchoreVuln,
        "get_nvd_scores",
        lambda self, ver: setattr(self, f"nvd_cvss_{ver}_vector", "mock_nvd_score"),
    )
    monkeypatch.setattr(
        AnchoreVuln,
        "get_vendor_nvd_scores",
        lambda self, ver: setattr(
            self, f"vendor_cvss_{ver}_vector", "mock_vendor_score"
        ),
    )
    monkeypatch.setattr(
        AnchoreVuln,
        "get_identifiers",
        lambda self: setattr(self, "identifiers", [*self.identifiers, mock_extra_vuln]),
    )
    mock_anchore_vuln = AnchoreVuln(**mock_anchore_vuln_args)
    assert mock_anchore_vuln.fix == "sorted_fix"
    assert mock_anchore_vuln.description == "new_description"
    assert mock_anchore_vuln.identifiers == [mock_anchore_vuln.vuln, mock_extra_vuln]
    assert mock_anchore_vuln.nvd_cvss_v2_vector == "mock_nvd_score"
    assert mock_anchore_vuln.nvd_cvss_v3_vector == "mock_nvd_score"
    assert mock_anchore_vuln.vendor_cvss_v2_vector == "mock_vendor_score"
    assert mock_anchore_vuln.vendor_cvss_v3_vector == "mock_vendor_score"
