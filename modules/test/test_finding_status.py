import pytest
import os
import sys
import json
from unittest import mock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vat_container_status import _check_findings  # noqa E402
from vat_container_status import is_approved  # noqa E402
from vat_container_status import _is_accredited  # noqa E402
from vat_container_status import _check_expiration  # noqa E402
from vat_container_status import _get_approval_status  # noqa E402


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
            "inheritsFrom": "redhat/ubi/ubi8:8.4",
            "contributor": {
                "state": "needs_review",
                "justification": "Upstream patched in version 8.44 on 2/10/2020. RH has not patched.",
            },
        },
        {
            "identifier": "CCE-13141516",
            "source": "oscap_comp",
            "severity": "Medium",
            "findingsState": "notapproved",
            "fastTrackEligibility": ["FT01"],
            "inheritsFrom": "",
            "contributor": {
                "state": "needs_review",
                "justification": "this is a compliance finding",
            },
        },
        {
            "identifier": "CCE-131516",
            "source": "oscap_comp",
            "severity": "Medium",
            "findingsState": "approved",
            "fastTrackEligibility": ["FT01"],
            "inheritsFrom": "",
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
            "inheritsFrom": "opensource/jupyter/jupyterlab:3.1.13",
            "contributor": {
                "state": "has_justification",
                "justification": "this is an anchore finding",
            },
        },
    ]


@pytest.fixture
def mock_vat_response():
    with open("modules/test/mocks/mock_vat_response.json") as f:
        return json.load(f)


@pytest.fixture
def bad_mock_vat_response():
    with open("modules/test/mocks/mock_vat_response_not_accredited.json") as f:
        return json.load(f)


@mock.patch.dict(os.environ, {"CI_COMMIT_BRANCH": "example"})
def test_is_approved(mock_vat_response, bad_mock_vat_response):
    # os.environ['CI_COMMIT_BRANCH'] = "example"
    # monkeypatch.setattr(os, 'environ', "example")
    assert is_approved(mock_vat_response, None) == (
        True,
        0,
        "Approved",
        "Auto Approval derived from previous version redhat/ubi/ubi8:8.4-fips",
    )
    assert is_approved(bad_mock_vat_response, None) == (
        True,
        0,
        "Not Accredited",
        "Auto Approval derived from previous version redhat/ubi/ubi8:8.4-fips",
    )


def test_is_accredited(mock_vat_response, bad_mock_vat_response):
    assert _is_accredited(mock_vat_response) == True  # noqa E712
    assert _is_accredited(bad_mock_vat_response) == False  # noqa E712


def test_check_expiration(mock_vat_response, bad_mock_vat_response):
    assert _check_expiration(mock_vat_response) == True  # noqa E712
    assert _check_expiration(bad_mock_vat_response) == False  # noqa E712


def test_get_approval_status():
    assert (
        _get_approval_status(
            exists=True,
            accredited=True,
            not_expired=True,
            ft_ineligible_findings=False,
            branch="development",
            force_approval=False,
        )
        == True  # noqa E712
    )
    assert (
        _get_approval_status(
            exists=True,
            accredited=True,
            not_expired=True,
            ft_ineligible_findings=True,
            branch="development",
            force_approval=False,
        )
        == False  # noqa E712
    )


def test_check_findings(mock_vat_resp_findings):
    only_ft_findings = {"findings": mock_vat_resp_findings[0:1]}
    only_non_ft_findings = {"findings": mock_vat_resp_findings[-1:]}
    ft_and_non_ft_findings = {"findings": mock_vat_resp_findings}
    assert _check_findings(only_ft_findings) == (True, False)
    assert _check_findings(only_non_ft_findings) == (False, True)
    assert _check_findings(ft_and_non_ft_findings) == (True, True)
