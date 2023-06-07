#!/usr/bin/env python3

import pathlib
import subprocess
from dataclasses import dataclass
from subprocess import CalledProcessError
from unittest.mock import mock_open

import boto3
import pytest
import requests
from requests.auth import HTTPBasicAuth

from ironbank.pipeline.abstract_artifacts import AbstractArtifact
from ironbank.pipeline.artifacts import (
    ContainerArtifact,
    GithubArtifact,
    HttpArtifact,
    S3Artifact,
)
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import GenericSubprocessError, InvalidURLList

log = logger.setup("test_artifacts")

mock_http_url = "http://example.com/example.txt"
mock_s3_url = "s3://example-test/example.txt"
mock_s3_url_version_id = "s3://example-test/example.txt?versionId=1.0"
mock_s3_url_extra_args_unused = "s3://example-test/example.txt?versionId=1.0&test=test"
mock_docker_url = "docker://example.com/example:1.0"
mock_github_url = "docker://ghcr.io/example:1.0"
mock_github_deprecated_url = "docker://docker.pkg.github.com/example:1.0"
mock_filename = "example.txt"
mock_tag = "example:1.0"


def add_s3_vars(monkeypatch):
    # mock_key123
    monkeypatch.setenv(
        "S3_ACCESS_KEY_test",
        "bW9ja19rZXkxMjM=",
    )
    # mock_key123
    monkeypatch.setenv(
        "S3_SECRET_KEY_test",
        "bW9ja19rZXkxMjM=",
    )


@pytest.fixture(autouse=True)
def mock_pull_auth(monkeypatch):
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "example")


@pytest.fixture
def mock_s3_artifact(monkeypatch):
    add_s3_vars(monkeypatch)
    return S3Artifact(
        url=mock_s3_url, filename=mock_filename, auth={"id": "test", "region": "test"}
    )


@pytest.fixture
def mock_s3_artifact_version_id(monkeypatch):
    add_s3_vars(monkeypatch)
    return S3Artifact(
        url=mock_s3_url_version_id,
        filename=mock_filename,
        auth={"id": "test", "region": "test"},
    )


@pytest.fixture
def mock_s3_artifact_extra_args_unused(monkeypatch):
    add_s3_vars(monkeypatch)
    return S3Artifact(
        url=mock_s3_url_extra_args_unused,
        filename=mock_filename,
        auth={"id": "test", "region": "test"},
    )


@pytest.fixture
def mock_s3_artifact_no_auth():
    return S3Artifact(url=mock_s3_url, filename=mock_filename)


@pytest.fixture
def mock_http_artifact():
    return HttpArtifact(url=mock_http_url, filename=mock_filename)


@pytest.fixture
def mock_container_artifact():
    return ContainerArtifact(url=mock_docker_url, tag=mock_tag)


@pytest.fixture
def mock_github_artifact(monkeypatch):
    # mock_key123
    monkeypatch.setenv(
        "GITHUB_ROBOT_USER",
        "bW9ja19rZXkxMjM=",
    )
    # mock_key123
    monkeypatch.setenv(
        "GITHUB_ROBOT_TOKEN",
        "bW9ja19rZXkxMjM=",
    )
    return GithubArtifact(url=mock_github_url, tag=mock_tag)


@pytest.fixture
def mock_deprecated_github_artifact():
    return GithubArtifact(url=mock_github_deprecated_url, tag=mock_tag)


@dataclass
class MockBoto3:
    type: str
    aws_access_key_id: str
    aws_secret_access_key: str
    region_name: str

    def download_file(self, bucket, object_name, local_path, extra_args):
        log.info("Reached download")
        log.info(f"Extra args: {extra_args}")


def test_s3_artifact_get_credentials(mock_s3_artifact):
    username, password, region = mock_s3_artifact.get_credentials()
    assert username == "mock_key123"
    assert password == "mock_key123"
    assert region == "test"


def test_s3_artifact_download(
    monkeypatch,
    caplog,
    mock_s3_artifact,
    mock_s3_artifact_no_auth,
    mock_s3_artifact_version_id,
    mock_s3_artifact_extra_args_unused,
):
    def mock_boto3(*args, **kwargs):
        return MockBoto3(*args, **kwargs)

    monkeypatch.setattr(boto3, "client", mock_boto3)

    with pytest.raises(ValueError) as ve:
        mock_s3_artifact_no_auth.download()
    assert ve.type == ValueError
    caplog.clear()

    mock_s3_artifact.download()
    assert "Reached download" in caplog.text
    assert "Extra args: {}" in caplog.text
    caplog.clear()

    mock_s3_artifact_version_id.download()
    assert "Reached download" in caplog.text
    assert "Extra args: {'VersionId': '1.0'}" in caplog.text
    caplog.clear()

    mock_s3_artifact_extra_args_unused.download()
    assert "Reached download" in caplog.text
    # this should confirm the additional args aren't being picked up
    assert "Extra args: {'VersionId': '1.0'}" in caplog.text
    caplog.clear()


def test_http_artifact_get_credentials(monkeypatch, mock_http_artifact):
    monkeypatch.setattr(
        AbstractArtifact, "get_username_password", lambda x: ("example", "test")
    )
    assert mock_http_artifact.get_credentials() == HTTPBasicAuth("example", "test")


def test_http_artifact_download(
    monkeypatch, mock_http_artifact, mock_responses  # noqa W0404
):
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data=b"example"))
    monkeypatch.setattr(HttpArtifact, "get_credentials", lambda self: "example")

    status_code = None
    monkeypatch.setattr(requests, "get", mock_responses["500"])
    with pytest.raises(InvalidURLList) as inv:
        status_code = mock_http_artifact.download()
    assert status_code is None
    assert inv.type == InvalidURLList

    monkeypatch.setattr(requests, "get", mock_responses["200"])
    status_code = mock_http_artifact.download()
    assert status_code == 200


def test_container_artifact_get_credentials(monkeypatch, mock_container_artifact):
    monkeypatch.setattr(
        AbstractArtifact, "get_username_password", lambda x: ("example", "test")
    )
    assert mock_container_artifact.get_credentials() == "example:test"


def test_container_artifact_download(
    monkeypatch, caplog, mock_container_artifact, raise_
):
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: False)
    monkeypatch.setattr(
        AbstractArtifact, "delete_artifact", lambda self: log.info("deleting artifact")
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, check: type(
            "MockSubprocessResponse",
            (),
            {"stdout": "exampleout", "stderr": "exampleerr"},
        ),
    )
    mock_container_artifact.download()
    assert "Successfully pulled" in caplog.text
    caplog.clear()

    monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    mock_container_artifact.download()
    assert "Found existing container artifact, deleting file" in caplog.text

    caplog.clear()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, check: raise_(CalledProcessError(1, ["example"])),
    )
    with pytest.raises(GenericSubprocessError):
        mock_container_artifact.download()
    assert "Successfully pulled" not in caplog.text


def test_github_artifact_un_pw(mock_github_artifact):
    username, password = mock_github_artifact.get_username_password()
    assert username == "mock_key123"
    assert password == "mock_key123"
