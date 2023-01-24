#!/usr/bin/env python3

import os
import sys
import yaml
import pytest
import pathlib
from subprocess import CalledProcessError
from requests.exceptions import HTTPError
from ironbank.pipeline.utils import logger
from botocore.exceptions import ClientError
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.utils.exceptions import InvalidURLList
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.artifacts import (
    S3Artifact,
    HttpArtifact,
    ContainerArtifact,
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import downloader  # noqa E402

log = logger.setup("test_downloader")


@pytest.fixture
def mock_docker_resources():
    return [
        {
            "auth": {"type": "basic"},
            "tag": "registry.access.redhat.com/ubi8:8.5",
            "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
        },
        {
            "tag": "registry.access.redhat.com/ubi8:8.5",
            "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
        },
    ]


@pytest.fixture
def mock_github_resources():
    return [
        {
            "tag": "abc",
            "url": "docker://docker.pkg.github.com/abc",
        },
        {
            "tag": "xyz",
            "url": "docker://ghcr.io/xyz",
        },
    ]


@pytest.fixture
def mock_http_resources():
    return [
        {
            "url": "http://example.com/artifact-name.txt",
            "filename": "artifact.txt",
            "validation": {},
        }
    ]


@pytest.fixture
def mock_s3_resources():
    return [
        {
            "url": "s3://example.com/artifact-name.txt",
            "filename": "artifact.txt",
            "validation": {},
        }
    ]


@pytest.fixture
def mock_bad_scheme_resources():
    return [{"url": "abcdef://example.example/cool/cool/cool:1.0", "tag": "cool:1.0"}]


@pytest.fixture
def mock_bad_auth_type():
    return {
        "resources": [
            {
                "auth": {"type": "anything_else"},
                "tag": "registry.access.redhat.com/ubi8:8.5",
                "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
            },
        ]
    }


@pytest.fixture
def mock_downloads():
    with pathlib.Path(
        os.getcwd(), "stages", "import-artifacts", "tests", "mhm.yaml"
    ).open() as f:
        return yaml.safe_load(f)


@pytest.fixture
def mock_artifacts_path():
    return "/path/fakepath"


@pytest.fixture
def mock_urls():
    return {
        "docker_string": "docker://",
        "http_string": "http",
        "s3_string": "s3://",
        "github_string_deprecated": "docker.pkg.github.com/",
        "github_string_current": "ghcr.io",
    }


# TODO: update all DsopProject and HardeningManifest __init__ mocks to use patch
def test_main_class_assignment(
    monkeypatch,
    caplog,
    mock_urls,
    mock_bad_scheme_resources,
    mock_docker_resources,
    mock_github_resources,
    mock_http_resources,
    mock_s3_resources,
):
    def mock_dsop_init(self):
        self.hardening_manifest_path = "lol"

    def mock_hm_init(self, hm_path):
        self.resources = []

    def patch_artifact(artifact_class, mock_dsop, mock_hm):
        monkeypatch.setattr(
            artifact_class, "download", lambda self: self.log.info(self)
        )
        monkeypatch.setattr(artifact_class, "delete_artifact", lambda x: None)
        if hasattr(artifact_class, "validate_checksum"):
            monkeypatch.setattr(artifact_class, "validate_checksum", lambda x: None)

        monkeypatch.setattr(DsopProject, "__init__", mock_dsop)
        monkeypatch.setattr(HardeningManifest, "__init__", mock_hm)

    log.info("Test exit 0 on empty resources section")
    with pytest.raises(SystemExit) as se:
        monkeypatch.setattr(DsopProject, "__init__", mock_dsop_init)
        monkeypatch.setattr(HardeningManifest, "__init__", mock_hm_init)
        downloader.main()
    assert se.value.code == 0
    caplog.clear()

    log.info("Test exit 0 on bad URL scheme")

    def mock_hm_init_bad_scheme(self, hm_path):
        self.resources = mock_bad_scheme_resources

    with pytest.raises(SystemExit) as se:
        monkeypatch.setattr(DsopProject, "__init__", mock_dsop_init)
        monkeypatch.setattr(HardeningManifest, "__init__", mock_hm_init_bad_scheme)
        downloader.main()
    assert se.value.code == 1
    caplog.clear()

    log.info("Test use of correct class for each HTTP scheme")

    def mock_hm_init_s3(self, hm_path):
        self.resources = mock_s3_resources

    with pytest.raises(SystemExit) as se:
        patch_artifact(S3Artifact, mock_dsop_init, mock_hm_init_s3)
        downloader.main()
    assert se.value.code == 0
    assert "S3Artifact" in caplog.text
    assert (
        "HttpArtifact" not in caplog.text
        and "GithubArtifact" not in caplog.text
        and "ContainerArtifact" not in caplog.text
    )
    caplog.clear()

    def mock_hm_init_github(self, hm_path):
        self.resources = mock_github_resources

    with pytest.raises(SystemExit) as se:
        patch_artifact(ContainerArtifact, mock_dsop_init, mock_hm_init_github)
        downloader.main()
    assert se.value.code == 0
    assert "GithubArtifact" in caplog.text
    assert "HttpArtifact" not in caplog.text and "S3Artifact" not in caplog.text
    caplog.clear()

    def mock_hm_init_docker(self, hm_path):
        self.resources = mock_docker_resources

    with pytest.raises(SystemExit) as se:
        patch_artifact(ContainerArtifact, mock_dsop_init, mock_hm_init_docker)
        downloader.main()
    assert se.value.code == 0
    assert "ContainerArtifact" in caplog.text
    assert (
        "S3Artifact" not in caplog.text
        and "GithubArtifact" not in caplog.text
        and "HttpArtifact" not in caplog.text
    )
    caplog.clear()

    def mock_hm_init_http(self, hm_path):
        self.resources = mock_http_resources

    with pytest.raises(SystemExit) as se:
        patch_artifact(HttpArtifact, mock_dsop_init, mock_hm_init_http)
        downloader.main()
    assert se.value.code == 0
    assert "HttpArtifact" in caplog.text
    assert (
        "S3Artifact" not in caplog.text
        and "GithubArtifact" not in caplog.text
        and "ContainerArtifact" not in caplog.text
    )
    caplog.clear()


# TODO: update all DsopProject and HardeningManifest __init__ mocks to use patch
def test_main_exceptions(monkeypatch, caplog, mock_s3_resources):
    def mock_dsop_init(self):
        self.hardening_manifest_path = "lol"

    def mock_hm_init(self, hm_path):
        self.resources = mock_s3_resources

    monkeypatch.setattr(DsopProject, "__init__", mock_dsop_init)
    monkeypatch.setattr(HardeningManifest, "__init__", mock_hm_init)

    log.info("Test various exceptions are caught and handled as expected")

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(KeyError("bad key")),
        )
        downloader.main()
    assert "The following key does not have a value: 'bad key'" in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(AssertionError("bad assertion")),
        )
        downloader.main()
    assert "Assertion Error: bad assertion" in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(InvalidURLList("invalid url")),
        )
        downloader.main()
    assert "No valid urls provided for" in caplog.text
    caplog.clear()

    class MockResponse:
        def __init__(self, status_code):
            self.status_code = status_code

    class MockHTTPError(HTTPError):
        def __init__(self, status_code):
            self.response = MockResponse(status_code)

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(MockHTTPError(400)),
        )
        downloader.main()
    assert "Error downloading" in caplog.text
    caplog.clear()

    class MockClientError(ClientError):
        def __init__(self, error_response, operation_name):
            pass

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(MockClientError("yes", "no")),
        )
        downloader.main()
    assert "S3 client error occurred" in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            S3Artifact,
            "download",
            lambda self: raise_(CalledProcessError("example", ["example"])),
        )
        downloader.main()
    assert (
        "Resource failed to pull, please check hardening_manifest.yaml configuration"
        in caplog.text
    )
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(S3Artifact, "download", lambda self: raise_(RuntimeError))
        downloader.main()
    assert "Unexpected runtime error occurred" in caplog.text
    caplog.clear()

    with pytest.raises(SystemExit):
        monkeypatch.setattr(S3Artifact, "download", lambda self: raise_(Exception))
        downloader.main()
    assert "Unexpected error occurred. Exception class:" in caplog.text
    caplog.clear()
