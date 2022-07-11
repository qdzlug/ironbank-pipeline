import json
import os
import sys
import pathlib
import pytest
import dockerfile


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.testing import raise_  # noqa E402
from utils.package_parser import (
    DockerfileParser,
    SbomFileParser,
)  # noqa E402
from utils.exceptions import DockerfileParseError  # noqa E402
from utils.types import Package  # noqa #402

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent, "mocks"
)


@pytest.fixture
def first_good_from_list():
    return [
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
            start_line=5,
            end_line=5,
            flags=(),
            value=("${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",),
        )
    ]


@pytest.fixture
def second_good_from_list():
    return [
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM $BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",
            start_line=5,
            end_line=5,
            flags=(),
            value=("$BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",),
        )
    ]


@pytest.fixture
def bad_from_list():
    return [
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM ubuntu:20.04",
            start_line=5,
            end_line=5,
            flags=(),
            value=("ubuntu:20.04",),
        )
    ]


@pytest.fixture
def dockerfile_tuple():
    return (
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
            start_line=5,
            end_line=5,
            flags=(),
            value=("${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",),
        ),
    )


def test_remove_non_from_statements(dockerfile_tuple):
    assert DockerfileParser.remove_non_from_statements(dockerfile_tuple) == [
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
            start_line=5,
            end_line=5,
            flags=(),
            value=("${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",),
        )
    ]


def test_validate_final_from(
    first_good_from_list, second_good_from_list, bad_from_list
):
    assert (
        DockerfileParser.validate_final_from(first_good_from_list) == False
    )  # noqa E712
    assert (
        DockerfileParser.validate_final_from(second_good_from_list) == False
    )  # noqa E712
    assert DockerfileParser.validate_final_from(bad_from_list) == True  # noqa E712


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


def test_sbom_file_parser(monkeypatch):
    monkeypatch.setattr(
        json,
        "load",
        lambda x: {
            "artifacts": [
                {
                    "type": "rpm",
                    "name": "package_name",
                    "version": "1.2.9-2.el8.noarch.rpm",
                }
            ]
        },
    )
    parsed_sbom = SbomFileParser.parse("example")
    assert parsed_sbom == [Package(kind="rpm", name="package_name", version="1.2.9-2")]
