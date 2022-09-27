#!/usr/bin/env python3

import pytest
import os
import pathlib
from unittest import mock
from ironbank.pipeline import vat_container_status
from ironbank.pipeline.vat_container_status import (
    _check_findings,
    is_approved,
    _is_accredited,
    _check_expiration,
    _get_approval_status,
)

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")


@pytest.fixture
def mock_vat_resp_findings():
    return [
        {
            "identifier": "CVE-45678",
            "scannerName": "Twistlock CVE",
            "severity": "Low",
            "package": "pcre-8.42-4.el8",
            "fastTrackEligibility": ["FT01"],
            "inheritsFrom": "redhat/ubi/ubi8:8.4",
            "justificationGate": {
                "justification": "Upstream patched in version 8.44 on 2/10/2020. RH has not patched.",
            },
            "state": {
                "findingStatus": "needs_review",
            },
        },
        {
            "identifier": "CCE-13141516",
            "scannerName": "OSCAP Compliance",
            "severity": "Medium",
            "findingsState": "notapproved",
            "fastTrackEligibility": ["FT01"],
            "inheritsFrom": "",
            "justificationGate": {
                "justification": "this is a compliance finding",
            },
            "state": {
                "findingStatus": "needs_review",
            },
        },
        {
            "identifier": "CCE-131516",
            "scannerName": "OSCAP Compliance",
            "severity": "Medium",
            "findingsState": "approved",
            "fastTrackEligibility": ["FT01"],
            "inheritsFrom": "",
            "justificationGate": {
                "justification": "this is a compliance finding",
            },
            "state": {
                "findingStatus": "needs_review",
            },
        },
        {
            "identifier": "CVE-9101112",
            "scannerName": "anchore_cve",
            "severity": "Critical",
            "package": "libssh-0.9.4-2.el8",
            "findingsState": "notapproved",
            "inheritsFrom": "opensource/jupyter/jupyterlab:3.1.13",
            "justificationGate": {
                "justification": "this is an anchore finding",
            },
            "state": {
                "findingStatus": "has_justification",
            },
        },
    ]


@pytest.fixture
def mock_vat_response():
    return {
        "image": {
            "imageName": "",
            "tag": "",
            "vatUrl": "https://vat-is-cool.org",
            "state": {
                "imageStatus": "Approved",
                "reason": "Auto Approval example",
                "factors": {"caReview": {"value": "Approved"}},
            },
        }
    }


@pytest.fixture
def bad_mock_vat_response():
    return {
        "image": {
            "imageName": "",
            "tag": "",
            "vatUrl": "https://vat-is-cool.org",
            "state": {
                "imageStatus": "Not Accredited",
                "reason": "It bad",
                "factors": {"caReview": {"expiration": "2021-09-16T04:00:00.000Z"}},
            },
        }
    }


@mock.patch.dict(os.environ, {"CI_COMMIT_BRANCH": "example"})
def test_is_approved(monkeypatch, mock_vat_response, bad_mock_vat_response):
    # os.environ['CI_COMMIT_BRANCH'] = "example"
    # monkeypatch.setattr(os, 'environ', "example")
    monkeypatch.setattr(vat_container_status, "_is_accredited", lambda x: True)
    monkeypatch.setattr(vat_container_status, "_check_expiration", lambda x: True)
    monkeypatch.setattr(vat_container_status, "_check_findings", lambda x: ([], []))
    monkeypatch.setattr(
        vat_container_status, "_get_approval_status", lambda x, y, z, a, b, c: True
    )
    assert is_approved(mock_vat_response, None) == (
        True,
        0,
        "Approved",
        "Auto Approval example",
    )
    # setting is_accidited to false has no effect
    monkeypatch.setattr(vat_container_status, "_is_accredited", lambda x: False)
    monkeypatch.setattr(vat_container_status, "_check_expiration", lambda x: True)
    monkeypatch.setattr(vat_container_status, "_check_findings", lambda x: ([], []))
    # this mock overrides the result of _is_accredited
    monkeypatch.setattr(
        vat_container_status, "_get_approval_status", lambda x, y, z, a, b, c: False
    )
    assert is_approved(bad_mock_vat_response, None) == (
        False,
        100,
        "Not Accredited",
        "It bad",
    )


def test_is_accredited(mock_vat_response, bad_mock_vat_response):
    assert _is_accredited(mock_vat_response["image"]) == True  # noqa E712
    assert _is_accredited(bad_mock_vat_response["image"]) == False  # noqa E712


def test_check_expiration(mock_vat_response, bad_mock_vat_response):
    assert _check_expiration(mock_vat_response["image"]) == True  # noqa E712
    assert _check_expiration(bad_mock_vat_response["image"]) == False  # noqa E712


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
