import pytest
import pathlib
from pathlib import Path
from unittest.mock import mock_open
from ironbank.pipeline.utils import logger
from mocks.mock_classes import MockProject, MockPath
from ironbank.pipeline.utils.exceptions import SymlinkFoundError


log = logger.setup("test_project")


def test_validate(monkeypatch):
    mock_project = MockProject()
    monkeypatch.setattr(MockProject, "validate_no_symlinked_files", lambda self: None)
    monkeypatch.setattr(MockProject, "validate_files_exist", lambda self: None)
    monkeypatch.setattr(MockProject, "validate_trufflehog_config", lambda self: None)
    monkeypatch.setattr(MockProject, "validate_dockerfile", lambda self: None)
    mock_project.validate()


def test_validate_no_symlinked_files(monkeypatch):
    mock_project = MockProject(dockerfile_path=Path("exampleDockerfile"))
    mock_project.validate_no_symlinked_files()

    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(SymlinkFoundError) as sfe:
        mock_project.validate_no_symlinked_files()

    assert "Symlink found for dockerfile_path, failing pipeline" == sfe.value.args[0]


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
