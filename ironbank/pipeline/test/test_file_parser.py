#!/usr/bin/env python3

from dataclasses import dataclass
import pytest
import pathlib
import dockerfile
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.file_parser import DockerfileParser
from ironbank.pipeline.utils.exceptions import DockerfileParseError

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")

log = logger.setup("test_file_parser")


@dataclass
class MockDockerfile:
    value: list[str] = "mock_value"
    cmd: str = "mock_cmd"


def test_parse(monkeypatch):
    monkeypatch.setattr(DockerfileParser, "parse_dockerfile", lambda x: x)
    monkeypatch.setattr(DockerfileParser, "remove_non_from_statements", lambda x: x)
    monkeypatch.setattr(DockerfileParser, "validate_final_from", lambda x: x)
    mock_result = DockerfileParser.parse("mock_filepath")
    assert mock_result == "mock_filepath"


def test_remove_non_from_statements():
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


def test_validate_final_from():
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


def test_parse_dockerfile(monkeypatch):
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
