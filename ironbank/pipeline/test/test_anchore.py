#!/usr/bin/env python3

import json
import pytest
import pathlib
import requests
import subprocess
from unittest.mock import mock_open
from ironbank.pipeline.utils import logger
from ironbank.pipeline.anchore import Anchore


log = logger.setup("test_anchore")


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    """Remove requests.sessions.Session.request for all tests."""
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def mock_vulnerability_resp():
    return {
        "vulnerabilities": [
            {
                "namespace": "rhel:8",
                "affected_packages": "These are affected",
                "description": "this is a description",
            },
        ]
    }


@pytest.fixture
def mock_vulnerability_resp_no_desc():
    return {
        "vulnerabilities": [
            {
                "namespace": "rhel:8",
                "affected_packages": "All of them",
                "description": None,
            },
        ]
    }


@pytest.fixture
def mock_vulnerability():
    return {
        "vuln": "CVE-3022-12345",
        "feed_group": "rhel:8",
        "description": "this is a description",
    }


@pytest.fixture
def full_mock_vulnerability_resp():
    return {
        "vulnerabilities": [
            {
                "namespace": "rhel:8",
                "affected_packages": "These are affected",
                "feed_group": "not-vulndb",
                "description": "this is a description",
                "extra": None,
            },
        ]
    }


@pytest.fixture
def extra_data_vulnerability_resp():
    return {
        "vuln_data": {
            "namespace": "rhel:8",
            "affected_packages": "All of them",
            "description": None,
        },
    }


@pytest.fixture
def compliance_data_resp():
    with open("ironbank/pipeline/test/mocks/mock_anchore_compliance.json", "r") as f:
        return json.load(f)


@pytest.fixture
def mock_anchore_object():
    return Anchore(
        url="http://test.anchore.dso.mil",
        username="test",
        password="test",
        verify=False,
    )


def test_get_anchore_api(monkeypatch, caplog, mock_responses, mock_anchore_object):

    monkeypatch.setattr(requests, "get", mock_responses["200"])
    log.info("Test successful anchore api json request")
    assert mock_anchore_object._get_anchore_api_json("", "", False) == {
        "status_code": 200,
        "text": "successful_request",
    }

    log.info("Test 404 from anchore throws exception if ignore is False")
    with pytest.raises(Exception) as e:
        monkeypatch.setattr(requests, "get", mock_responses["404"])
        mock_anchore_object._get_anchore_api_json("", "", False)
    assert "Non-200 response from Anchore 404 - not_found" in e.value.args
    caplog.clear()

    log.info("Test 404 with ignore set to True doesn't throw an exception")
    monkeypatch.setattr(requests, "get", mock_responses["404"])
    assert mock_anchore_object._get_anchore_api_json("", "", True) == None  # noqa E711
    assert "No ancestry detected" in caplog.text
    caplog.clear()

    log.info("Test request exception results has expected output")
    with pytest.raises(requests.RequestException):
        monkeypatch.setattr(requests, "get", mock_responses["requestException"])
        mock_anchore_object._get_anchore_api_json("", "", False)
    assert "Failed to connect with Anchore" in caplog.text
    caplog.clear()

    log.info("Test json decode error raises base exception")
    with pytest.raises(Exception) as e:
        monkeypatch.setattr(requests, "get", mock_responses["jsonDecodeError"])
        mock_anchore_object._get_anchore_api_json("", "", False)
    assert "Got 200 response but is not valid JSON" in e.value.args


def test_get_parent_sha(monkeypatch, mock_anchore_object):

    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: [{"imageDigest": "12345"}],
    )
    log.info("Test successful parent sha retrieval")
    assert mock_anchore_object._get_parent_sha("12345") == "12345"

    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: None)
    log.info("Test None is returned on no ancestry")
    assert mock_anchore_object._get_parent_sha("12345") == None  # noqa E711


def test_get_version(monkeypatch, caplog, mock_anchore_object):
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: {"service": {"version": "4.0.2"}},
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))

    log.info("")
    mock_anchore_object.get_version("./test-artifacts")
    assert "Anchore Enterprise Version: 4.0.2" in caplog.text
    caplog.clear


def test_get_extra_vuln_data(
    monkeypatch,
    mock_vulnerability_resp,
    mock_vulnerability,
    mock_vulnerability_resp_no_desc,
    mock_anchore_object,
):
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: mock_vulnerability_resp,
    )

    assert mock_anchore_object._get_extra_vuln_data(mock_vulnerability) == {
        "vuln_data": mock_vulnerability_resp["vulnerabilities"][0]
    }

    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: mock_vulnerability_resp_no_desc,
    )
    assert mock_anchore_object._get_extra_vuln_data(mock_vulnerability) == {
        "vuln_data": mock_vulnerability_resp_no_desc["vulnerabilities"][0]
    }


def test_get_vulns(
    monkeypatch,
    full_mock_vulnerability_resp,
    extra_data_vulnerability_resp,
    mock_anchore_object,
):
    monkeypatch.setattr(
        Anchore, "_get_parent_sha", lambda self, x: "sha256-123456789012345"
    )
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: full_mock_vulnerability_resp,
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(json, "dump", lambda x, y: None)
    monkeypatch.setattr(
        Anchore, "_get_extra_vuln_data", lambda self, x: extra_data_vulnerability_resp
    )

    assert (
        mock_anchore_object.get_vulns(
            "sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts"
        )
        == None  # noqa E711
    )

    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: None)
    assert (
        mock_anchore_object.get_vulns(
            "sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts"
        )
        == None  # noqa E711
    )

    monkeypatch.setattr(Anchore, "_get_extra_vuln_data", lambda *args, **kwargs: {})
    mock_anchore_object.get_vulns(
        "sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts"
    ) == None  # noqa E711


def test_get_compliance(monkeypatch, compliance_data_resp, mock_anchore_object):
    monkeypatch.setattr(
        Anchore, "_get_parent_sha", lambda self, x: "sha256-123456789012345"
    )
    monkeypatch.setattr(
        Anchore, "_get_anchore_api_json", lambda *args, **kwargs: compliance_data_resp
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(json, "dump", lambda x, y: None)

    assert (
        mock_anchore_object.get_compliance(
            "sha256:c03fec26436653fd06149d2ced7e63fb53bf97fe7270c0cdf928ff19412d7f91",
            "registry1.dso.mil/ironbank-staging/google/distroless/static:ibci-873812",
            "./test-artifacts",
        )
        == None  # noqa E711
    )

    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: None)
    assert (
        mock_anchore_object.get_compliance(
            "sha256:c03fec26436653fd06149d2ced7e63fb53bf97fe7270c0cdf928ff19412d7f91",
            "registry1.dso.mil/ironbank-staging/google/distroless/static:ibci-873812",
            "./test-artifacts",
        )
        == None  # noqa E711
    )


def test_image_add(monkeypatch, caplog, mock_responses, mock_anchore_object):
    monkeypatch.setattr(pathlib.Path, "is_file", lambda _: True)
    monkeypatch.setattr(subprocess, "run", mock_responses["0"])
    monkeypatch.setattr(
        json, "loads", lambda *args, **kwargs: [{"imageDigest": "sha256-12345678910"}]
    )

    assert (
        mock_anchore_object.image_add("image.dso.mil/imagename/tag")
        == "sha256-12345678910"
    )

    monkeypatch.setattr(subprocess, "run", mock_responses["1"])
    monkeypatch.setattr(
        json,
        "loads",
        lambda *args, **kwargs: {"detail": {"digest": "sha256-12345678910"}},
    )
    assert (
        mock_anchore_object.image_add("image.dso.mil/imagename/tag")
        == "sha256-12345678910"
    )
    assert "already exists in Anchore. Pulling current scan data." in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(subprocess, "run", mock_responses["2"])
        monkeypatch.setattr(
            json,
            "loads",
            lambda *args, **kwargs: {"detail": {"digest": "sha256-12345678910"}},
        )
        mock_anchore_object.image_add("image.dso.mil/imagename/tag")
        assert "canned_error" in caplog.text
    caplog.clear()


def test_generate_sbom(monkeypatch, caplog, mock_anchore_object):
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(pathlib.Path, "mkdir", lambda *args, **kwargs: None)
    mock_anchore_object.generate_sbom(
        "image.dso.mil/imagename/tag", "./test-artifacts", "spdx", "json"
    )
    assert "syft image.dso.mil/imagename/tag" in caplog.text
