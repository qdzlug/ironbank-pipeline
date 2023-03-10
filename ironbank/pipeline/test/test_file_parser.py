#!/usr/bin/env python3

import json
import pytest
import pathlib
import random
from unittest.mock import patch
from ironbank.pipeline.test.mocks.mock_classes import MockOutput, MockPackage, MockPath
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.package_parser import (
    NullPackage,
    GoPackage,
    RpmPackage,
    PypiPackage,
    NpmPackage,
    RubyGemPackage,
    AptPackage,
    ApkPackage,
)
from ironbank.pipeline.file_parser import (
    AccessLogFileParser,
    DockerfileParser,
    SbomFileParser,
)
from ironbank.pipeline.utils.exceptions import (
    RepoTypeNotSupported,
)

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")

log = logger.setup("test_file_parser")


@pytest.fixture
def mock_packages(monkeypatch):
    monkeypatch.setattr(NullPackage, "parse", lambda x: "NullPackage")
    monkeypatch.setattr(GoPackage, "parse", lambda x: "GoPackage")
    monkeypatch.setattr(RpmPackage, "parse", lambda x: "RpmPackage")
    monkeypatch.setattr(PypiPackage, "parse", lambda x: "PypiPackage")
    monkeypatch.setattr(NpmPackage, "parse", lambda x: "NpmPackage")
    monkeypatch.setattr(RubyGemPackage, "parse", lambda x: "RubyGemPackage")
    monkeypatch.setattr(ApkPackage, "parse", lambda x: "ApkPackage")
    monkeypatch.setattr(AptPackage, "parse", lambda x: "AptPackage")


@patch("ironbank.pipeline.file_parser.Path", new=MockPath)
def test_access_log_file_parser(monkeypatch, mock_packages):
    log.info("Test non 200 is skipped")
    mock_nexus_host = "https://nexus-example.com/"
    mock_repo = "example_repo"
    mock_pkg = "example_pkg"
    mock_url = f"{mock_nexus_host}{mock_repo}/{mock_pkg}"
    valid_repos = {mock_repo: mock_pkg}

    monkeypatch.setenv("NEXUS_HOST_URL", mock_nexus_host)
    monkeypatch.setenv("ACCESS_LOG_REPOS", "mock_value")

    monkeypatch.setattr(json, "load", lambda x: valid_repos)
    monkeypatch.setattr(AccessLogFileParser, "handle_file_obj", lambda x: x)
    assert AccessLogFileParser.parse([f"500 {mock_url}\n"]) == []

    log.info("Test value error raised on unparseable url")
    with pytest.raises(ValueError) as ve:
        assert AccessLogFileParser.parse(["200  \n"]) == []
    assert "Could not parse" in ve.value.args[0]

    log.info("Test repo type not supported raised on key missing from repos")
    with pytest.raises(RepoTypeNotSupported) as e:
        assert AccessLogFileParser.parse(
            [f"200 {mock_nexus_host}unsupported/unsupported\n"]
        )
    assert "Repository type not supported" in e.value.args[0]

    log.info("Test repo type not supported raised on default match case")
    with pytest.raises(RepoTypeNotSupported) as e:
        assert AccessLogFileParser.parse([f"200 {mock_url}\n"]) == []
    assert f"Repository type not supported: {mock_pkg}" in e.value.args

    test_cases = {
        "gosum": "NullPackage",
        "go": "GoPackage",
        "rpm": "RpmPackage",
        "pypi": "PypiPackage",
        "npm": "NpmPackage",
        "rubygem": "RubyGemPackage",
        "apk": "ApkPackage",
        "apt": "AptPackage",
    }

    log.info("Test successfully parsed package type and matched")
    for repo_type, pkg_type in test_cases.items():
        valid_repos[f"{mock_repo}"] = repo_type
        mock_url = f"{mock_nexus_host}{mock_repo}/{repo_type}"
        log.info(mock_url)
        assert AccessLogFileParser.parse([f"200 {mock_url}\n"]) == [pkg_type]


@patch("ironbank.pipeline.file_parser.Package", new=MockPackage)
def test_sbom_file_parser(monkeypatch):
    log.info("Test SBOM is successfully parsed")
    mock_package = {"type": "apt", "name": "example", "version": "1.0"}
    monkeypatch.setattr(SbomFileParser, "handle_file_obj", lambda x: x)
    parsed_packages = SbomFileParser.parse({"artifacts": [mock_package]})
    assert parsed_packages == [MockPackage(*list(mock_package.values()))]


@patch("ironbank.pipeline.file_parser.Path", new=MockPath)
def test_dockerfile_parse(monkeypatch):
    log.info("Test dockerfile is successfully parsed")
    monkeypatch.setattr(DockerfileParser, "remove_non_from_statements", lambda x: x)
    monkeypatch.setattr(DockerfileParser, "validate_final_from", lambda x: x)
    mock_result = DockerfileParser.parse("mock_filepath")
    assert mock_result == MockOutput().mock_data


def test_dockerfile_remove_non_from_statements():
    log.info("Test non from statements are filtered from tuple")
    mock_cmds = ["ENV abc", "ENTRYPOINT NONE", "ARG TEST", "RUN dnf install -y example"]
    mock_from_cmds = ["FROM mock_from_1", "FROM mock_from_2", "FROM mock_from_3"]
    mock_dockerfile = []
    for from_cmds in mock_from_cmds:
        mock_dockerfile.append(from_cmds)
        mock_dockerfile += [random.choice(mock_cmds) for _ in range(3)]
    filtered_dockerfile_cmds = DockerfileParser.remove_non_from_statements(
        mock_dockerfile
    )
    assert filtered_dockerfile_cmds == mock_from_cmds


def test_dockerfile_validate_final_from():
    log.info("Test final from in Dockerfile is valid")
    mock_from_stmts = ["FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"]
    assert DockerfileParser.validate_final_from(mock_from_stmts) is False
    log.info("Test final from in Dockefile is invalid")
    mock_from_stmts = ["FROM invalid_image:1.0"]
    assert DockerfileParser.validate_final_from(mock_from_stmts) is True
