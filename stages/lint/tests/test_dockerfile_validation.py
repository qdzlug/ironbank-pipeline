#!/usr/bin/env python3
import sys
import os
import logging
import pytest
import asyncio
import pathlib
from unittest.mock import patch

import dockerfile
from yaml import parse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.testing import raise_
from mocks.mock_classes import MockProject, MockHardeningManifest
import dockerfile_validation
from dockerfile_validation import (
    remove_non_from_statements,
    validate_final_from,
    parse_dockerfile,
)  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent.parent, "mocks"
)


@pytest.fixture
def good_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile.test-good").as_posix()


@pytest.fixture
def bad_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile.test-bad").as_posix()


@pytest.fixture
def nonexistent_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile").as_posix()


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
    assert remove_non_from_statements(dockerfile_tuple) == [
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
    assert validate_final_from(first_good_from_list) == False  # noqa E712
    assert validate_final_from(second_good_from_list) == False  # noqa E712
    assert validate_final_from(bad_from_list) == True  # noqa E712


def test_parse_dockerfile(monkeypatch):
    monkeypatch.setattr(dockerfile, "parse_file", lambda x: x)
    parsed_file = parse_dockerfile("example")
    assert parsed_file == "example"

    monkeypatch.setattr(
        dockerfile, "parse_file", lambda x: raise_(dockerfile.GoIOError)
    )
    with pytest.raises(SystemExit) as se:
        parsed_file = parse_dockerfile("example")
    assert se.value.code == 1

    monkeypatch.setattr(
        dockerfile, "parse_file", lambda x: raise_(dockerfile.GoParseError)
    )
    with pytest.raises(SystemExit) as se:
        parsed_file = parse_dockerfile("example")
    assert se.value.code == 1


@patch("dockerfile_validation.DsopProject", new=MockProject)
@patch("dockerfile_validation.HardeningManifest", new=MockHardeningManifest)
def test_dockerfile_validation_main(monkeypatch, caplog):
    monkeypatch.setattr("dockerfile_validation.parse_dockerfile", lambda x: x)
    monkeypatch.setattr("dockerfile_validation.remove_non_from_statements", lambda x: x)
    monkeypatch.setattr("dockerfile_validation.validate_final_from", lambda x: None)
    asyncio.run(dockerfile_validation.main())
    assert "Dockerfile is validated" in caplog.text

    monkeypatch.setattr("dockerfile_validation.validate_final_from", lambda x: x)
    with pytest.raises(SystemExit) as se:
        asyncio.run(dockerfile_validation.main())
    assert se.value.code == 100


# TODO: move this to an integration test file
@pytest.mark.integration
def test_parse_dockerfile_integration(
    good_dockerfile_path, bad_dockerfile_path, nonexistent_dockerfile_path
):
    assert parse_dockerfile(good_dockerfile_path) == (
        dockerfile.Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_REGISTRY=registry1.dso.mil",
            start_line=1,
            end_line=1,
            flags=(),
            value=("BASE_REGISTRY=registry1.dso.mil",),
        ),
        dockerfile.Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_IMAGE=ironbank/redhat/ubi/ubi8",
            start_line=2,
            end_line=2,
            flags=(),
            value=("BASE_IMAGE=ironbank/redhat/ubi/ubi8",),
        ),
        dockerfile.Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_TAG=8.5",
            start_line=3,
            end_line=3,
            flags=(),
            value=("BASE_TAG=8.5",),
        ),
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

    assert parse_dockerfile(bad_dockerfile_path) == (
        dockerfile.Command(
            cmd="FROM",
            sub_cmd=None,
            json=False,
            original="FROM ubuntu:20.04",
            start_line=1,
            end_line=1,
            flags=(),
            value=("ubuntu:20.04",),
        ),
    )

    with pytest.raises(SystemExit) as exc_info:
        parse_dockerfile(nonexistent_dockerfile_path)

    assert exc_info.type == SystemExit
