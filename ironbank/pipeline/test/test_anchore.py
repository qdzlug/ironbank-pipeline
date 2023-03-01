#!/usr/bin/env python3

import json
import pytest
import pathlib
import requests
import subprocess
from unittest.mock import mock_open, patch
from ironbank.pipeline.test.mocks.mock_classes import MockPath, MockPopen
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.scanner_api_handlers.anchore import Anchore


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
def mock_compliance_data_resp():
    return [
        {
            "abc123": {
                "registry1.dso.mil/some/image:1.0": [
                    {
                        "detail": {
                            "result": {"result": {"1": "some_result"}, "image_id": "1"},
                        }
                    }
                ]
            }
        }
    ]


@pytest.fixture
def anchore_object():
    return Anchore(
        url="http://test.anchore.dso.mil",
        username="test",
        password="test",
        verify=False,
    )


def test_get_anchore_api(monkeypatch, caplog, mock_responses, anchore_object):
    monkeypatch.setattr(requests, "get", mock_responses["200"])
    log.info("Test successful anchore api json request")
    assert anchore_object._get_anchore_api_json("", "", False) == {
        "status_code": 200,
        "text": "successful_request",
    }

    log.info("Test 404 from anchore throws exception if ignore is False")
    with pytest.raises(Exception) as e:
        monkeypatch.setattr(requests, "get", mock_responses["404"])
        anchore_object._get_anchore_api_json("", "", False)
    assert "Non-200 response from Anchore 404 - not_found" in e.value.args
    caplog.clear()

    log.info("Test 404 with ignore set to True doesn't throw an exception")
    monkeypatch.setattr(requests, "get", mock_responses["404"])
    anchore_object._get_anchore_api_json("", "", True) is None
    assert "No ancestry detected" in caplog.text
    caplog.clear()

    log.info("Test request exception results has expected output")
    with pytest.raises(requests.RequestException):
        monkeypatch.setattr(requests, "get", mock_responses["requestException"])
        anchore_object._get_anchore_api_json("", "", False)
    assert "Failed to connect with Anchore" in caplog.text
    caplog.clear()

    log.info("Test json decode error raises base exception")
    with pytest.raises(Exception) as e:
        monkeypatch.setattr(requests, "get", mock_responses["jsonDecodeError"])
        anchore_object._get_anchore_api_json("", "", False)
    assert "Got 200 response but is not valid JSON" in e.value.args


def test_get_parent_sha(monkeypatch, anchore_object):
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: [{"imageDigest": "12345"}],
    )
    log.info("Test successful parent sha retrieval")
    assert anchore_object._get_parent_sha("12345") == "12345"

    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: None)
    log.info("Test None is returned on no ancestry")
    assert anchore_object._get_parent_sha("12345") is None


def test_get_version(monkeypatch, caplog, anchore_object):
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: {"service": {"version": "4.0.2"}},
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))

    log.info("Test successfully gather version info")
    anchore_object.get_version("./test-artifacts")
    assert "Anchore Enterprise Version: 4.0.2" in caplog.text
    caplog.clear


def test_get_extra_vuln_data(
    monkeypatch,
    mock_vulnerability_resp,
    mock_vulnerability,
    mock_vulnerability_resp_no_desc,
    anchore_object,
):
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: mock_vulnerability_resp,
    )

    log.info("Test successfully gather extra vuln data with description")
    assert anchore_object._get_extra_vuln_data(mock_vulnerability) == {
        "vuln_data": mock_vulnerability_resp["vulnerabilities"][0]
    }

    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda *args, **kwargs: mock_vulnerability_resp_no_desc,
    )
    log.info("Test successfully gather extra vuln data without description")
    assert anchore_object._get_extra_vuln_data(mock_vulnerability) == {
        "vuln_data": mock_vulnerability_resp_no_desc["vulnerabilities"][0]
    }


def test_get_vulns(
    monkeypatch,
    full_mock_vulnerability_resp,
    extra_data_vulnerability_resp,
    anchore_object,
):
    parent_sha = "sha256-123456789012345"
    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: parent_sha)

    urls = []
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        # using the or to allow the append to execute and then return the full mock data
        lambda self, url: urls.append(url) or full_mock_vulnerability_resp,
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(json, "dump", lambda x, y: None)
    monkeypatch.setattr(
        Anchore, "_get_extra_vuln_data", lambda self, x: extra_data_vulnerability_resp
    )

    log.info("Test successfully get vulns with parent data")
    args = ["sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts"]
    anchore_object.get_vulns(*args)
    # we can check the object returned by _get_anchore_api_json because it is directly updated in the function
    assert (
        full_mock_vulnerability_resp["vulnerabilities"][0]["extra"]
        == extra_data_vulnerability_resp["vuln_data"]
    )

    log.info("Verify parent digest sets correct url")
    assert f"?base_digest={parent_sha}" in urls[-1]

    log.info("Test no parent digest sets correct url")
    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: "")
    urls = []
    anchore_object.get_vulns(*args)
    assert f"?base_digest={parent_sha}" not in urls[-1]


def test_get_compliance(monkeypatch, mock_compliance_data_resp, anchore_object):
    parent_digest = "sha256-123456789012345"
    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: parent_digest)
    urls = []
    monkeypatch.setattr(
        Anchore,
        "_get_anchore_api_json",
        lambda self, url: urls.append(url) or mock_compliance_data_resp,
    )
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    results_data = []
    monkeypatch.setattr(json, "dump", lambda x, y: results_data.append(x))
    mock_digest = list(mock_compliance_data_resp[0].keys())[0]
    mock_image = list(mock_compliance_data_resp[0][mock_digest].keys())[0]
    args = [
        mock_digest,
        mock_image,
        "./test-artifacts",
    ]
    log.info("Test expected result is written to file")
    anchore_object.get_compliance(*args)
    image_id = mock_compliance_data_resp[0][mock_digest][mock_image][0]["detail"][
        "result"
    ]["image_id"]
    assert (
        results_data[-1][image_id]
        == mock_compliance_data_resp[0][mock_digest][mock_image][0]["detail"]["result"][
            "result"
        ][image_id]
    )

    log.info("Verify correct url is set when parent exists")
    assert f"&base_digest={parent_digest}" in urls[-1]

    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: None)
    urls = []
    results_data = []
    anchore_object.get_compliance(*args)
    log.info("Test no parent digest sets correct url")
    assert f"&base_digest={parent_digest}" not in urls[-1]


def test_image_add(monkeypatch, caplog, mock_responses, anchore_object):
    monkeypatch.setattr(pathlib.Path, "is_file", lambda _: True)
    mock_image = "image.dso.mil/imagename/tag"
    mock_digest = "sha256-12345678910"
    log.info("Test subprocess call returns 0 on successful image add")
    monkeypatch.setattr(subprocess, "run", mock_responses["0"])
    monkeypatch.setattr(
        json, "loads", lambda *args, **kwargs: [{"imageDigest": mock_digest}]
    )

    assert anchore_object.image_add(mock_image) == mock_digest

    log.info("Test subprocess call returns 1 on image already exists in anchore")
    monkeypatch.setattr(subprocess, "run", mock_responses["1"])
    monkeypatch.setattr(
        json,
        "loads",
        lambda *args, **kwargs: {"detail": {"digest": mock_digest}},
    )
    assert anchore_object.image_add(mock_image) == mock_digest
    assert "already exists in Anchore. Pulling current scan data." in caplog.text
    caplog.clear()

    log.info("Test subprocess error is captured and raises SystemExit")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: raise_(subprocess.CalledProcessError(100, [], "")),
    )
    with pytest.raises(SystemExit):
        anchore_object.image_add(mock_image)
    assert "Could not add image to Anchore" in caplog.text
    caplog.clear()

    log.info("Test image add raises SystemExit on non 0/1 return code")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(subprocess, "run", mock_responses["2"])
        monkeypatch.setattr(
            json,
            "loads",
            lambda *args, **kwargs: {"detail": {"digest": mock_digest}},
        )
        anchore_object.image_add(mock_image)
    assert "canned_error" in caplog.text
    caplog.clear()


def test_image_wait(monkeypatch, caplog, anchore_object):
    mock_digest = "sha256-12345678910"

    log.info("Test successful wait")
    mock_success_proc = MockPopen()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: mock_success_proc)
    anchore_object.image_wait(mock_digest)
    assert mock_success_proc.stdout.readline().strip() in caplog.text
    caplog.clear()

    log.info("Test system exit is raised after subprocess error")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            subprocess,
            "Popen",
            lambda *args, **kwargs: raise_(subprocess.SubprocessError([])),
        )
        anchore_object.image_wait(mock_digest)
    assert "Failed while waiting for Anchore to scan image" in caplog.text
    assert "data1" not in caplog.text
    caplog.clear()

    log.info("Test system exit is raised when returncode != 0")
    mock_failed_proc = MockPopen(returncode=50)
    with pytest.raises(SystemExit) as se:
        monkeypatch.setattr(
            subprocess, "Popen", lambda *args, **kwargs: mock_failed_proc
        )
        anchore_object.image_wait(mock_digest)
    assert 50 in se.value.args
    assert mock_failed_proc.stdout.read() in caplog.text
    assert mock_failed_proc.stderr.read() in caplog.text


@patch("pathlib.Path", new=MockPath)
def test_generate_sbom(monkeypatch, caplog, anchore_object):
    log.info("Test write sbom to default filename")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: None)

    def log_filename(self, other):
        self.log.info(other)
        return MockPath(self, other)

    monkeypatch.setattr(MockPath, "__truediv__", log_filename)
    args = ["image.dso.mil/imagename/tag", "./test-artifacts", "spdx", "json"]
    anchore_object.generate_sbom(*args)
    assert "sbom-spdx.json" in caplog.text
    assert "syft image.dso.mil/imagename/tag" in caplog.text
    caplog.clear()

    log.info("Test write sbom to provided filename")
    anchore_object.generate_sbom(
        *args,
        "example-filename",
    )
    assert "sbom-example-filename-spdx.json" in caplog.text
    assert "syft image.dso.mil/imagename/tag" in caplog.text
    caplog.clear()

    log.info("Test subprocess error raises system exit")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: raise_(subprocess.SubprocessError([])),
    )
    with pytest.raises(SystemExit):
        anchore_object.generate_sbom(*args)
    assert "Could not generate sbom of image" in caplog.text
    caplog.clear()
