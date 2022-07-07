import json
import os
import sys
import pathlib
import pytest
from pathlib import Path
import requests
from unittest.mock import patch, mock_open, Mock


sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from modules.anchore import Anchore  # noqa E402
from mocks.mock_responses import mock_responses  # noqa E402 W0611

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
            "extra": None
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
    with open("mocks/mock_anchore_compliance.json", "r") as f:
        return json.load(f)

def test_get_anchore_api(monkeypatch, mock_responses, caplog):
    monkeypatch.setattr(requests, "get", mock_responses["200"])
    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object._get_anchore_api_json("", "", False) == {'status_code': 200, 'text': 'successful_request'}

    with pytest.raises(Exception):
        monkeypatch.setattr(requests, "get", mock_responses["404"])
        anchore_object._get_anchore_api_json("", "", False)
        assert "Non-200 response from Anchore" in caplog.text
    caplog.clear()

    monkeypatch.setattr(requests, "get", mock_responses["404"])
    assert anchore_object._get_anchore_api_json("", "", True) == None
    assert "No ancestry detected" in caplog.text
    caplog.clear()

    with pytest.raises(requests.RequestException):
        monkeypatch.setattr(requests, "get", mock_responses["requestException"])
        anchore_object._get_anchore_api_json("", "", False)
        assert "Failed to connect with Anchore" in caplog.text
    caplog.clear()

    with pytest.raises(Exception):
        monkeypatch.setattr(requests, "get", mock_responses["jsonDecodeError"])
        anchore_object._get_anchore_api_json("", "", False)
        assert "Got 200 response but is not valid JSON" in caplog.text

def test_get_parent_sha(monkeypatch):
    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: [{"imageDigest": "12345"}])
    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object._get_parent_sha("12345") == "12345"

    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: None)
    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object._get_parent_sha("12345") == None

def test_get_version(monkeypatch, caplog):
    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: {"service": {"version": "4.0.2"}})
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))

    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)

    anchore_object.get_version("./test-artifacts")
    assert "Anchore Enterprise Version: 4.0.2" in caplog.text
    caplog.clear


def test_get_extra_vuln_data(monkeypatch, mock_vulnerability_resp, mock_vulnerability, mock_vulnerability_resp_no_desc):
    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: mock_vulnerability_resp)

    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object._get_extra_vuln_data(mock_vulnerability) == {"vuln_data": mock_vulnerability_resp["vulnerabilities"][0]}

    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: mock_vulnerability_resp_no_desc)
    assert anchore_object._get_extra_vuln_data(mock_vulnerability) == {"vuln_data": mock_vulnerability_resp_no_desc["vulnerabilities"][0]}

def test_get_vulns(monkeypatch, full_mock_vulnerability_resp, extra_data_vulnerability_resp):
    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: "sha256-123456789012345")
    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: full_mock_vulnerability_resp)
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(json, "dump", lambda x,y: None)
    monkeypatch.setattr(Anchore, "_get_extra_vuln_data", lambda self, x: extra_data_vulnerability_resp)

    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object.get_vulns("sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts") == None

    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: None)
    assert anchore_object.get_vulns("sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts") == None

    monkeypatch.setattr(Anchore, "_get_extra_vuln_data", lambda *args, **kwargs:  {})
    anchore_object.get_vulns("sha256-104237896510837456108", "registry1.dso.mil", "./test-artifacts") == None

def test_get_compliance(monkeypatch, compliance_data_resp):
    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: "sha256-123456789012345")
    monkeypatch.setattr(Anchore, "_get_anchore_api_json", lambda *args, **kwargs: compliance_data_resp)
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(json, "dump", lambda x,y: None)

    anchore_object = Anchore(url="http://test.anchore.dso.mil", username="test", password="test", verify=False)
    assert anchore_object.get_compliance("sha256:c03fec26436653fd06149d2ced7e63fb53bf97fe7270c0cdf928ff19412d7f91", "registry1.dso.mil/ironbank-staging/google/distroless/static:ibci-873812", "./test-artifacts") == None

    monkeypatch.setattr(Anchore, "_get_parent_sha", lambda self, x: None)
    assert anchore_object.get_compliance("sha256:c03fec26436653fd06149d2ced7e63fb53bf97fe7270c0cdf928ff19412d7f91", "registry1.dso.mil/ironbank-staging/google/distroless/static:ibci-873812", "./test-artifacts") == None