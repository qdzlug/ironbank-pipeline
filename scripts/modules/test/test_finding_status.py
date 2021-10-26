import pytest
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vat_container_status import _check_findings  # noqa E402


@pytest.fixture
def mock_vat_resp_findings():
    return [
        {
            "identifier": "CVE-45678",
            "source": "twistlock_cve",
            "severity": "Low",
            "package": "pcre-8.42-4.el8",
            "findingsState": "under review",
            "fastTrackEligibility": ["FT01"],
            "contributor": {
                "state": "needs_review",
                "justification": "Upstream patched in version 8.44 on 2/10/2020. RH has not patched.",
            },
        },
        {
            "identifier": "CCE-13141516",
            "source": "oscap_comp",
            "severity": "Medium",
            "findingsState": "approved",
            "fastTrackEligibility": ["FT01"],
            "contributor": {
                "state": "needs_review",
                "justification": "this is a compliance finding",
            },
        },
        {
            "identifier": "CVE-9101112",
            "source": "anchore_cve",
            "severity": "Critical",
            "package": "libssh-0.9.4-2.el8",
            "findingsState": "notapproved",
            "contributor": {
                "state": "has_justification",
                "justification": "this is an anchore finding",
            },
        },
    ]


def test_check_findings(mock_vat_resp_findings):
    only_ft_findings = {"findings": mock_vat_resp_findings[0:1]}
    only_non_ft_findings = {"findings": mock_vat_resp_findings[-1:]}
    ft_and_non_ft_findings = {"findings": mock_vat_resp_findings}
    assert _check_findings(only_ft_findings) == (True, False)
    assert _check_findings(only_non_ft_findings) == (False, True)
    assert _check_findings(ft_and_non_ft_findings) == (True, True)
