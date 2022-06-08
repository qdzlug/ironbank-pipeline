import sys
import os
from unittest import mock
import pytest
import pathlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from abstract_artifacts import AbstractArtifact, AbstractFileArtifact

from utils import logger

log = logger.setup("test_abstract_artifacts")


class MockArtifact(AbstractArtifact):
    def get_credentials():
        pass

    def download():
        pass


class MockFileArtifact(AbstractFileArtifact):
    def get_credentials():
        pass

    def download():
        pass


example_url = "http://example.com/example.test"


@pytest.fixture
def mock_artifact():
    return MockArtifact(url=example_url)


@pytest.fixture
def mock_artifact_with_dir(monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", "example")
    return MockArtifact(url=example_url)


@pytest.fixture()
def mock_file_artifact():
    return MockFileArtifact(url=example_url)


def test_artifact_init(mock_artifact, mock_artifact_with_dir):
    assert mock_artifact.dest_path == pathlib.Path("None")
    assert mock_artifact_with_dir.dest_path == pathlib.Path("example")


@pytest.mark.only
def test_artifact_delete(monkeypatch, caplog, mock_artifact):
    monkeypatch.setattr(pathlib.Path, "exists", lambda x: False)
    monkeypatch.setattr(pathlib.Path, "is_file", lambda x: False)
    monkeypatch.setattr(os, "remove", lambda x: log.info("remove"))
    mock_artifact.delete_artifact()
    assert "File deleted" not in caplog.text

    monkeypatch.setattr(pathlib.Path, "exists", lambda x: True)
    monkeypatch.setattr(pathlib.Path, "is_file", lambda x: True)
    monkeypatch.setattr(os, "remove", lambda x: log.info("remove"))
    mock_artifact.delete_artifact()
    assert "File deleted" in caplog.text
