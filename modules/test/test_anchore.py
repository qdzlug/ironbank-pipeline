import json
import os
import sys
import pathlib
import pytest
import dockerfile
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
            "description": "this is a description",
            "affected_packages": "These are affected"
        },
        ]
    }

@pytest.fixture
def mock_vulnerability():
    return {
        "vulnerabilities": [
        {
        "feed_group": "rhel:8",
        "description": "this is a description",
        },
        ]
    }


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

