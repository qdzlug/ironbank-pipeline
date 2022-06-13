import hashlib
import sys
import os
import pytest
from dataclasses import dataclass
import pathlib
from unittest.mock import mock_open

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from abstract_artifacts import AbstractArtifact, AbstractFileArtifact  # noqa E402

from utils import logger  # noqa E402

log = logger.setup("test_abstract_artifacts")


@dataclass
class MockArtifact(AbstractArtifact):
    def __post_init__(self):
        super().__post_init__()

    def get_credentials():
        pass

    def download():
        pass


@dataclass
class MockFileArtifact(AbstractFileArtifact):
    def __post_init__(self):
        super().__post_init__()

    def get_credentials():
        pass

    def download():
        pass


example_url = "http://example.com/example.test"


@pytest.fixture
def mock_artifact(monkeypatch):
    monkeypatch.delenv("ARTIFACT_DIR", raising=False)
    return MockArtifact(url=example_url, filename="example.txt")


@pytest.fixture
def mock_artifact_with_dir(monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", "example")
    return MockArtifact(url=example_url, filename="example.txt")


@pytest.fixture
def mock_artifact_with_basic_auth(monkeypatch):
    # encoded text is example_un
    monkeypatch.setenv("CREDENTIAL_USERNAME_test", "ZXhhbXBsZV91bg==")
    # encoded text is example_pw
    monkeypatch.setenv("CREDENTIAL_PASSWORD_test", "ZXhhbXBsZV9wdw==")
    return MockArtifact(url=example_url, filename="example.txt", auth={"id": "test"})


@pytest.fixture
def mock_file_artifact(monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", "example")
    return MockFileArtifact(
        url=example_url,
        filename="abc",
        validation={
            "type": "sha256",
            "value": "b9104c364781d253ee4c26220cbbef4a486037613629662aa5e97b7e6a97e897",
        },
    )


@pytest.fixture()
def mock_file_artifact_bad_validation(monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", "example")
    return MockFileArtifact(
        url=example_url,
        filename="abc",
        validation={
            "type": "md5",
            "value": "b9104c364781d253ee4c26220cbbef4a486037613629662aa5e97b7e6a97e897",
        },
    )


def test_artifact_init(mock_artifact, mock_artifact_with_dir):
    assert mock_artifact.dest_path == pathlib.Path("None")
    assert mock_artifact_with_dir.dest_path == pathlib.Path("example")


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


def test_username_password(mock_artifact_with_basic_auth):
    username, password = mock_artifact_with_basic_auth.get_username_password()
    assert username == "example_un"
    assert password == "example_pw"


def test_file_artifact_init(mock_file_artifact):
    assert mock_file_artifact.dest_path == pathlib.Path("example/external-resources")
    assert mock_file_artifact.artifact_path == pathlib.Path(
        "example/external-resources/abc"
    )


def test_validate_checksum(
    monkeypatch, caplog, mock_file_artifact, mock_file_artifact_bad_validation
):
    @dataclass
    class MockGenerateChecksum:
        checksum: str

        def hexdigest(self):
            return self.checksum

    with pytest.raises(ValueError) as ve:
        mock_file_artifact_bad_validation.validate_checksum()
    assert ve.type == ValueError

    # match sha
    monkeypatch.setattr(
        AbstractFileArtifact,
        "generate_checksum",
        lambda self: MockGenerateChecksum(
            "b9104c364781d253ee4c26220cbbef4a486037613629662aa5e97b7e6a97e897"
        ),
    )
    mock_file_artifact.validate_checksum()
    assert "Checksum validated" in caplog.text
    caplog.clear()
    # no match sha
    with pytest.raises(AssertionError) as ae:
        monkeypatch.setattr(
            AbstractFileArtifact,
            "generate_checksum",
            lambda self: MockGenerateChecksum(
                "061277afcd391ddc24c2032aa320fa31722fcc3b006703610f9a49e3d8f8549d"
            ),
        )
        mock_file_artifact.validate_checksum()
    assert ae.type == AssertionError
    assert "Checksum validated" not in caplog.text


def test_generate_checksum(monkeypatch, mock_file_artifact):
    # TODO: move this to a Mock file
    @dataclass
    class MockHashlib:
        type: str
        fake_hash: str = ""

        def update(self, chunk):
            self.fake_hash += chunk

    monkeypatch.setattr(hashlib, "new", lambda self: MockHashlib("sha256"))
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    result = mock_file_artifact.generate_checksum()
    assert result.fake_hash == "data"


def test_validate_filename():
    mock_filename_artifact1 = MockFileArtifact(url=example_url, filename="abc.txt")
    mock_filename_artifact2 = MockFileArtifact(url=example_url, filename="1abc.txt")
    mock_bad_filename_artifact1 = MockFileArtifact(
        url=example_url, filename="../../abc.txt"
    )
    mock_bad_filename_artifact2 = MockFileArtifact(
        url=example_url, filename="\\/../abc.txt"
    )
    mock_bad_filename_artifact3 = MockFileArtifact(url=example_url, filename="@abc.txt")

    # shouldn't throw error for valid file
    mock_filename_artifact1.validate_filename()

    mock_filename_artifact2.validate_filename()

    with pytest.raises(ValueError) as ve:
        mock_bad_filename_artifact1.validate_filename()
    assert ve.type == ValueError

    with pytest.raises(ValueError) as ve:
        mock_bad_filename_artifact2.validate_filename()
    assert ve.type == ValueError

    with pytest.raises(ValueError) as ve:
        mock_bad_filename_artifact3.validate_filename()
    assert ve.type == ValueError
