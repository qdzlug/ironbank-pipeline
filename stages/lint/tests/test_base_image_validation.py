#!/usr/bin/env python3
from dataclasses import dataclass
import json
import pathlib
import subprocess
import sys
import os
import logging
from unittest.mock import patch
from unittest.mock import mock_open
import pytest
import asyncio


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_image_validation import skopeo_inspect_base_image  # noqa E402
import base_image_validation # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


@pytest.fixture
def good_base_image():
    return ["redhat/ubi/ubi8", "8.5"]


@pytest.fixture
def bad_base_image():
    return ["redhat/ubi/ubi8", "8.100"]


# @dataclass
# class MockOpen:

#     def __enter__():
#         return MockOpen()

#     def __exit__():
#         pass

# @dataclass
# class MockPath():

#     mock_file_path_one: str = "mocked_file"
#     mock_file_path_two: str = "mocked_file"

#     def write_text(self, *args, **kwargs):
#         pass

#     # def open(self, write_mode):
#     #     return MockOpen()
@dataclass
class MockSubprocessReturn:
    stdout: str = "standard out"


def mock_subprocess_run(*args, **kwargs):
    return MockSubprocessReturn("data")


def mock_subprocess_fail(*args, **kwargs):
    raise subprocess.CalledProcessError(1, ["cmd"])


# TODO: add this to a module
def raise_(e):
    raise e


def test_skopeo_inspect_base_image(monkeypatch, caplog, good_base_image):
    monkeypatch.setenv("STAGING_BASE_IMAGE", "base")
    monkeypatch.setenv(
        "DOCKER_AUTH_CONFIG_STAGING", "c3RhZ2luZy10ZXN0Cg=="
    )  # staging-test -> base64 encoded value
    monkeypatch.setattr(pathlib.Path, "write_text", lambda self, x: True)
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    monkeypatch.setenv("ARTIFACT_DIR", "right/here")
    monkeypatch.setattr(json, "dump", lambda x, y: True)

    skopeo_inspect_base_image(good_base_image[0], good_base_image[1])
    assert "staging_pull_auth.json" in caplog.text
    caplog.clear()

    monkeypatch.delenv("STAGING_BASE_IMAGE")
    monkeypatch.setenv("DOCKER_AUTH_CONFIG_PULL", "c3RhZ2luZy10ZXN0Cg==")

    skopeo_inspect_base_image(good_base_image[0], good_base_image[1])
    assert "prod_pull_auth.json" in caplog.text
    caplog.clear()

    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)

    with pytest.raises(SystemExit):
        skopeo_inspect_base_image(good_base_image[0], good_base_image[1])

    assert (
        "Failed to inspect BASE_IMAGE:BASE_TAG provided in hardening_manifest."
        in caplog.text
    )
    caplog.clear()

    monkeypatch.setattr(subprocess, "run", lambda self: raise_(Exception))

    with pytest.raises(SystemExit):
        skopeo_inspect_base_image(good_base_image[0], good_base_image[1])

    assert "Unknown failure when attemping to inspect BASE_IMAGE" in caplog.text
    caplog.clear()


@dataclass
class MockProject:
    example: str = "nah"
    hardening_manifest_path = "example_path"


@dataclass
class MockHardeningManifest:
    base_image_name: str = "example"
    base_image_tag: str = "1.0"


@pytest.mark.only
@patch("project.DsopProject", new=MockProject)
@patch("hardening_manifest.HardeningManifest", new=MockHardeningManifest)
@patch("base_image_validation.skopeo_inspect_base_image", lambda x, y: "blah")
def test_base_image_validation_main():
    asyncio.run(base_image_validation.main())
