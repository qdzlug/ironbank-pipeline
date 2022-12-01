#!/usr/bin/env python3

from dataclasses import dataclass
import json
import re
from unittest.mock import patch
import pytest
import pathlib
import dockerfile
from ironbank.pipeline.test.mocks.mock_classes import MockPackage, MockPath
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.file_parser import (
    AccessLogFileParser,
    DockerfileParser,
    SbomFileParser,
)
from ironbank.pipeline.utils.exceptions import DockerfileParseError

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")

log = logger.setup("test_file_parser")


@dataclass
class MockRE:
    compiled_pattern: str = None
    match_obj: str = None
    group_name: str = None

    @classmethod
    def compile(cls, pattern: str):
        return cls(compiled_pattern=pattern)

    @staticmethod
    def escape(unformatted: str):
        return unformatted

    def match(self, match_obj):
        return MockRE(compiled_pattern=self.compiled_pattern, match_obj=match_obj)

    def group(self, group_item: str):
        return MockRE(
            compiled_pattern=self.compiled_pattern,
            match_obj=self.match_obj,
            group_name=group_item,
        )


@pytest.mark.only
@patch("ironbank.pipeline.file_parser.Path", new=MockPath)
def test_access_log_file_parser(monkeypatch):

    valid_repos = ["moke_repo1", "moke_repo2"]
    monkeypatch.setenv("ACCESS_LOG_REPOS", "mock_value")
    monkeypatch.setattr(json, "load", lambda x: valid_repos)
    monkeypatch.setattr(re, "compile", MockRE.compile)
    # monkeypatch.setattr(re,"escape", lambda x: x)
    monkeypatch.setattr(AccessLogFileParser, "handle_file_obj", lambda x: x)
    assert AccessLogFileParser.parse(["500 example\n"]) == []


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
