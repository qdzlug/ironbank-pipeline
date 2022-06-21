#!/usr/bin/env python3
import sys
import os
import logging
import pytest
import asyncio
import pathlib
from unittest.mock import patch

import dockerfile
from modules.utils.exceptions import DockerfileParseError

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.testing import raise_  # noqa E402
from utils.package_parser import DockerfileParser  # noqa E402
from utils.exceptions import DockerfileParseError  # noqa E402
from utils.testing import raise_  # noqa E402
from mocks.mock_classes import MockProject, MockHardeningManifest  # noqa E402
import dockerfile_validation  # noqa E402

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent.parent, "mocks"
)

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


@pytest.fixture
def good_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile.test-good").as_posix()


@pytest.fixture
def bad_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile.test-bad").as_posix()


@pytest.fixture
def nonexistent_dockerfile_path():
    return pathlib.Path(mock_path, "Dockerfile").as_posix()


@patch("dockerfile_validation.DsopProject", new=MockProject)
@patch("dockerfile_validation.HardeningManifest", new=MockHardeningManifest)
def test_dockerfile_validation_main(monkeypatch, caplog):

    monkeypatch.setattr(DockerfileParser, "parse", lambda x: [])
    asyncio.run(dockerfile_validation.main())
    assert "Dockerfile is validated" in caplog.text

    monkeypatch.setattr(DockerfileParser, "parse", lambda x: x)
    with pytest.raises(SystemExit) as se:
        asyncio.run(dockerfile_validation.main())
    assert se.value.code == 100

    monkeypatch.setattr(
        DockerfileParser, "parse", lambda x: raise_(DockerfileParseError)
    )
    with pytest.raises(SystemExit) as se:
        asyncio.run(dockerfile_validation.main())
    assert se.value.code == 1

    monkeypatch.setattr(DockerfileParser, "parse", lambda x: raise_(Exception))
    with pytest.raises(SystemExit) as se:
        asyncio.run(dockerfile_validation.main())
    assert se.value.code == 1


# TODO: move this to an integration test file
@pytest.mark.integration
def test_parse_dockerfile_integration(
    good_dockerfile_path, bad_dockerfile_path, nonexistent_dockerfile_path
):
    assert DockerfileParser.parse_dockerfile(good_dockerfile_path) == (
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

    assert DockerfileParser.parse_dockerfile(bad_dockerfile_path) == (
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

    with pytest.raises(DockerfileParseError) as exc_info:
        DockerfileParser.parse_dockerfile(nonexistent_dockerfile_path)

    assert exc_info.type == DockerfileParseError
