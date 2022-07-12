import pytest
import sys
import os
import pathlib
from unittest.mock import mock_open

from mocks.mock_classes import MockProject, MockPath


def test_validate_files_exist(monkeypatch):
    mock_project = MockProject()
    monkeypatch.setattr(MockPath, "exists", lambda self: True)
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: False)
    mock_project.validate_files_exist()

    with pytest.raises(AssertionError) as ae:
        monkeypatch.setattr(MockPath, "exists", lambda self: True)
        monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
        mock_project.validate_files_exist()

    assert "Jenkinsfile found" in ae.value.args[0]


def test_validate_clamav_whitelist_config(monkeypatch, caplog):

    monkeypatch.setenv("CLAMAV_WHITELIST", 1)
    monkeypatch.setattr(MockPath, "exists", lambda self: True)
    mock_project = MockProject()
    mock_project.validate_clamav_whitelist_config()

    monkeypatch.setenv("CLAMAV_WHITELIST", "")
    monkeypatch.setattr(MockPath, "exists", lambda self: False)
    mock_project = MockProject()
    mock_project.validate_clamav_whitelist_config()

    with pytest.raises(SystemExit) as se:
        monkeypatch.setenv("CLAMAV_WHITELIST", "True")
        monkeypatch.setattr(MockPath, "exists", lambda self: False)
        mock_project = MockProject()
        mock_project.validate_clamav_whitelist_config()
    assert se.value.code == 1
    assert (
        "CLAMAV_WHITELIST CI variable exists but clamav-whitelist file not found"
        in caplog.text
    )
    caplog.clear()

    with pytest.raises(SystemExit) as se:
        monkeypatch.setenv("CLAMAV_WHITELIST", "")
        monkeypatch.setattr(MockPath, "exists", lambda self: True)
        mock_project = MockProject()
        mock_project.validate_clamav_whitelist_config()
    assert se.value.code == 1
    assert "clamav-whitelist file found but CLAMAV_WHITELIST CI variable does not exist"
    caplog.clear()


def test_validate_trufflehog_config(monkeypatch, caplog):
    with pytest.raises(AssertionError):
        monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
        mock_project = MockProject()
        mock_project.validate_trufflehog_config()

    monkeypatch.setattr(pathlib.Path, "exists", lambda self: False)
    monkeypatch.setattr(MockPath, "exists", lambda self: False)
    mock_project = MockProject()
    mock_project.validate_trufflehog_config()

    with pytest.raises(SystemExit) as se:
        monkeypatch.setattr(MockPath, "exists", lambda self: True)
        monkeypatch.setenv("TRUFFLEHOG_CONFIG", "")
        mock_project = MockProject()
        mock_project.validate_trufflehog_config()
    assert se.value.code == 1
    assert (
        "trufflehog-config file found but TRUFFLEHOG_CONFIG CI variable does not exist"
        in caplog.text
    )
    caplog.clear()


def test_validate_dockerfile(monkeypatch, caplog):
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="FROM a\nRUN b"))
    mock_project = MockProject(dockerfile_path=pathlib.Path("."))
    mock_project.validate_dockerfile()
    assert "LABEL" not in caplog.text

    with pytest.raises(AssertionError):
        monkeypatch.setattr(
            pathlib.Path, "open", mock_open(read_data="FROM a\nLABEL b\nRUN c")
        )
        mock_project = MockProject(dockerfile_path=pathlib.Path("."))
        mock_project.validate_dockerfile()
        assert "LABEL" in caplog.text
