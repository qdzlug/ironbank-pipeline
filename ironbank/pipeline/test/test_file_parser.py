#!/usr/bin/env python3

from dataclasses import dataclass
import json
from unittest.mock import patch
import pytest
import pathlib
import dockerfile
from ironbank.pipeline.test.mocks.mock_classes import MockPackage, MockPath
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.package_parser import (
    NullPackage,
    GoPackage,
    YumPackage,
    PypiPackage,
    NpmPackage,
    RubyGemPackage,
    AptPackage,
)
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.file_parser import (
    AccessLogFileParser,
    DockerfileParser,
    SbomFileParser,
)
from ironbank.pipeline.utils.exceptions import (
    DockerfileParseError,
    RepoTypeNotSupported,
)

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")

log = logger.setup("test_file_parser")


@pytest.fixture
def mock_packages(monkeypatch):
    monkeypatch.setattr(NullPackage, "parse", lambda x: "NullPackage")
    monkeypatch.setattr(GoPackage, "parse", lambda x: "GoPackage")
    monkeypatch.setattr(YumPackage, "parse", lambda x: "YumPackage")
    monkeypatch.setattr(PypiPackage, "parse", lambda x: "PypiPackage")
    monkeypatch.setattr(NpmPackage, "parse", lambda x: "NpmPackage")
    monkeypatch.setattr(RubyGemPackage, "parse", lambda x: "RubyGemPackage")
    monkeypatch.setattr(AptPackage, "parse", lambda x: "AptPackage")


@pytest.mark.only
@patch("ironbank.pipeline.file_parser.Path", new=MockPath)
def test_access_log_file_parser(monkeypatch, mock_packages):
    log.info("Test non 200 is skipped")
    mock_nexus_host = "https://nexus-example.com/"
    mock_repo = "example_repo"
    mock_pkg = "example_pkg"
    mock_url = f"{mock_nexus_host}{mock_repo}/{mock_pkg}"
    valid_repos = {mock_repo: mock_pkg}

    monkeypatch.setenv("NEXUS_HOST", mock_nexus_host)
    monkeypatch.setenv("ACCESS_LOG_REPOS", "mock_value")

    monkeypatch.setattr(json, "load", lambda x: valid_repos)
    monkeypatch.setattr(AccessLogFileParser, "handle_file_obj", lambda x: x)
    assert AccessLogFileParser.parse([f"500 {mock_url}\n"]) == []

    with pytest.raises(ValueError) as ve:
        assert AccessLogFileParser.parse(["200  \n"]) == []
    assert "Could not parse" in ve.value.args[0]

    with pytest.raises(RepoTypeNotSupported) as e:
        assert AccessLogFileParser.parse(
            [f"200 {mock_nexus_host}unsupported/unsupported\n"]
        )
    assert "Repository type not supported" in e.value.args[0]

    with pytest.raises(RepoTypeNotSupported) as e:
        assert AccessLogFileParser.parse([f"200 {mock_url}\n"]) == []
    assert f"Repository type not supported: {mock_pkg}" in e.value.args

    test_cases = {
        "gosum": "NullPackage",
        "go": "GoPackage",
        "yum": "YumPackage",
        "pypi": "PypiPackage",
        "npm": "NpmPackage",
        "rubygem": "RubyGemPackage",
        "apt": "AptPackage",
    }

    for repo_type, pkg_type in test_cases.items():
        valid_repos[f"{mock_repo}"] = repo_type
        mock_url = f"{mock_nexus_host}{mock_repo}/{repo_type}"
        log.info(mock_url)
        assert AccessLogFileParser.parse([f"200 {mock_url}\n"]) == [pkg_type]


@pytest.mark.only
@patch("ironbank.pipeline.file_parser.Package", new=MockPackage)
def test_sbom_file_parser(monkeypatch):
    mock_package = {"type": "apt", "name": "example", "version": "1.0"}
    monkeypatch.setattr(SbomFileParser, "handle_file_obj", lambda x: x)
    parsed_packages = SbomFileParser.parse({"artifacts": [mock_package]})
    assert parsed_packages == [MockPackage(*list(mock_package.values()))]


@dataclass
class MockDockerfile:
    value: list[str] = "mock_value"
    cmd: str = "mock_cmd"


def test_dockerfile_parse(monkeypatch):
    log.info("Test dockerfile is successfully parsed")
    monkeypatch.setattr(DockerfileParser, "parse_dockerfile", lambda x: x)
    monkeypatch.setattr(DockerfileParser, "remove_non_from_statements", lambda x: x)
    monkeypatch.setattr(DockerfileParser, "validate_final_from", lambda x: x)
    mock_result = DockerfileParser.parse("mock_filepath")
    assert mock_result == "mock_filepath"


def test_dockerfile_remove_non_from_statements():
    log.info("Test non from statements are filtered from tuple")
    mock_from_cmd = MockDockerfile(cmd="From")
    mock_dockerfile_tuple = (
        MockDockerfile(cmd="RUN"),
        mock_from_cmd,
        MockDockerfile(cmd="example"),
    )
    filtered_dockerfile_cmds = DockerfileParser.remove_non_from_statements(
        mock_dockerfile_tuple
    )
    assert filtered_dockerfile_cmds == [mock_from_cmd]


def test_dockerfile_validate_final_from():
    log.info("Test final from in Dockerfile is valid")
    mock_from_stmts = ["${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"]
    assert (
        DockerfileParser.validate_final_from([MockDockerfile(value=mock_from_stmts)])
        is False
    )
    log.info("Test final from in Dockefile is invalid")
    mock_from_stmts = ["invalid_image:1.0"]
    assert (
        DockerfileParser.validate_final_from([MockDockerfile(value=mock_from_stmts)])
        is True
    )


def test_dockerfile_parse_dockerfile(monkeypatch):
    monkeypatch.setattr(dockerfile, "parse_file", lambda x: x)
    parsed_file = DockerfileParser.parse_dockerfile("example")
    assert parsed_file == "example"

    monkeypatch.setattr(
        dockerfile, "parse_file", lambda x: raise_(dockerfile.GoIOError)
    )
    with pytest.raises(DockerfileParseError) as se:
        parsed_file = DockerfileParser.parse_dockerfile("example")
    assert se.type == DockerfileParseError

    monkeypatch.setattr(
        dockerfile, "parse_file", lambda x: raise_(dockerfile.GoParseError)
    )
    with pytest.raises(DockerfileParseError) as se:
        parsed_file = DockerfileParser.parse_dockerfile("example")
    assert se.type == DockerfileParseError
