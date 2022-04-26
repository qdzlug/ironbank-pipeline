#!/usr/bin/env python3
import sys
import os
import logging
import pytest

from dockerfile import Command

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dockerfile_validation import remove_non_from_statements  # noqa E402
from dockerfile_validation import validate_final_from  # noqa E402
from dockerfile_validation import parse_dockerfile  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")

@pytest.fixture
def good_dockerfile_path():
    return "tests/mock/Dockerfile.test-good"


@pytest.fixture
def bad_dockerfile_path():
    return "tests/mock/Dockerfile.test-bad"


@pytest.fixture
def nonexistent_dockerfile_path():
    return "tests/mock/Dockerfile"


@pytest.fixture
def first_good_from_list():
    return [
        Command(
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
        Command(
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
        Command(
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
        Command(
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
        Command(
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
    assert validate_final_from(first_good_from_list) == False
    assert validate_final_from(second_good_from_list) == False
    assert validate_final_from(bad_from_list) == True


def test_parse_dockerfile(
    good_dockerfile_path, bad_dockerfile_path, nonexistent_dockerfile_path
):
    assert parse_dockerfile(good_dockerfile_path) == (
        Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_REGISTRY=registry1.dso.mil",
            start_line=1,
            end_line=1,
            flags=(),
            value=("BASE_REGISTRY=registry1.dso.mil",),
        ),
        Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_IMAGE=ironbank/redhat/ubi/ubi8",
            start_line=2,
            end_line=2,
            flags=(),
            value=("BASE_IMAGE=ironbank/redhat/ubi/ubi8",),
        ),
        Command(
            cmd="ARG",
            sub_cmd=None,
            json=False,
            original="ARG BASE_TAG=8.5",
            start_line=3,
            end_line=3,
            flags=(),
            value=("BASE_TAG=8.5",),
        ),
        Command(
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
        Command(
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
