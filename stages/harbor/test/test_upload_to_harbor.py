#!/usr/bin/env python3

import asyncio
import hashlib
import os
from typing import Literal
import pytest
from pathlib import Path
import sys
from unittest import mock
import base64
import json
from requests import patch
from traitlets import Any
from ironbank.pipeline.test.mocks.mock_classes import (
    MockPath,
    MockPredicates,
    MockSkopeo,
)
import pathlib
import yaml
import subprocess
from dataclasses import dataclass
from ironbank.pipeline.image import Image
from ironbank.pipeline.test.mocks.mock_classes import (
    MockImage,
    MockOutput,
    MockPath,
    MockPopen,
    MockJson,
    MockResponse,
)
from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.image import Image
from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import subprocess_error_handler
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject
from unittest.mock import patch, mock_open, Mock
from stages.harbor.upload_to_harbor import compare_digests
import pytest
import logging
from ironbank.pipeline.utils.predicates import Predicates


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import upload_to_harbor


log = logger.setup("test_upload_to_harbor")


@pytest.fixture
def mock_pipeline_vat_response():
    return """{
    "images": [
        {
            "image_name": "pipeline_image",
            "image_id": "1234567890"
        }
    ]
}"""


@pytest.fixture
def mock_pipeline_parent_vat_response():
    return """{
    "images": [
        {
            "image_name": "pipeline_image",
            "image_id": "1234567890"
        }
    ]
}"""


@pytest.fixture
def mock_dir():
    return {
        "license": "v1",
        "readme.md": "exampleread",
    }


@pytest.fixture
def mock_hm_content():
    return {
        "apiVersion": "v1",
        "name": "example/example/exampleimage",
        "tags": ["8.6.7_5309", "latest"],
        "args": {"BASE_IMAGE": "redhat/ubi/ubi8", "BASE_TAG": "8.5"},
        "labels": {
            "org.opencontainers.image.title": "exampleimage",
            "org.opencontainers.image.description": "lengthy string words more words and even more words",
            "org.opencontainers.image.licenses": "lol",
            "org.opencontainers.image.url": "https://invalid.com",
            "org.opencontainers.image.vendor": "Example Image",
            "org.opencontainers.image.version": "8.6.7.5309",
            "mil.dso.ironbank.image.keywords": "awesome,verycool,example",
            "mil.dso.ironbank.image.type": "opensource",
            "mil.dso.ironbank.product.name": "Example Image",
        },
        "resources": [
            {
                "tag": "registry.example_image.com/exampleimage:8.6.7_5309",
                "url": "docker://registry.example_image.com/exampleimage@sha256:4d736d84721c8fa09d5b0f5988da5f34163d407d386cc80b62cbf933ea5124e8",
            }
        ],
        "maintainers": [
            {
                "email": "vendor@example.com",
                "name": "Vendor Person",
                "username": "v_endor",
            },
            {
                "name": "CHT Memeber",
                "username": "cht_memeber",
                "email": "cht_member@company.com",
                "cht_member": True,
            },
        ],
        "partner_advocates": [
            {
                "name": "Cht Member",
                "username": "cht_memb",
            },
        ],
    }


# @pytest.fixture
# class MockLog:
#     def __init__(self):
#         self.info_messages = []
#         self.error_messages = []


@patch("upload_to_harbor.Image", new=MockImage)
@patch("upload_to_harbor.Skopeo", new=MockSkopeo)
@patch("upload_to_harbor.Path", new=MockPath)
@patch("base_image_validation.json", new=MockJson)
def test_compare_digests_match(monkeypatch, caplog):
    # Mock the necessary environment variables

    monkeypatch.setenv(
        "IMAGE_PODMAN_SHA",
        "da3811154d59c4267077ddd8bb768fa9b06399c486e1fc00485116b57c9872f5",
    )
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_skopeo")
    monkeypatch.setattr(MockPath, "exists", lambda: True)
    # log.info("Test pulling manifest_file with skopeo")
    monkeypatch.setattr(
        MockSkopeo,
        "inspect",
        lambda *args, **kwargs: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    )
    upload_to_harbor.compare_digests(
        image=Image(
            registry="registry",
            name="image_name",
            digest="digest",
            transport="docker://",
        )
    )
    assert "Digests match" in caplog.text


@patch("upload_to_harbor.Image", new=MockImage)
@patch("upload_to_harbor.Skopeo", new=MockSkopeo)
@patch("upload_to_harbor.Path", new=MockPath)
@patch("base_image_validation.json", new=MockJson)
def test_compare_digests_nonmatch(monkeypatch, caplog):
    # Mock the necessary environment variables

    monkeypatch.setenv(
        "IMAGE_PODMAN_SHA",
        "da3811154d59c4267077ddd8bb768fa9b06399c486ec00485116b57c9872f5",
    )
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_skopeo")
    monkeypatch.setattr(MockPath, "exists", lambda: True)
    # log.info("Test pulling manifest_file with skopeo")
    monkeypatch.setattr(
        MockSkopeo,
        "inspect",
        lambda *args, **kwargs: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    )

    with pytest.raises(SystemExit):
        upload_to_harbor.compare_digests(
            image=Image(
                registry="registry",
                name="image_name",
                digest="digest",
                transport="docker://",
            )
        )

    assert "Digests do not match" in caplog.text


# @patch("upload_to_harbor.Image", new=MockImage)
# @patch("upload_to_harbor.Skopeo", new=MockSkopeo)
# @patch("upload_to_harbor.Path", new=MockPath)
# def test_promote_tags(monkeypatch, caplog):
#     # set the env
#     monkeypatch.setenv(
#         "DOCKER_AUTH_FILE_PRE_PUBLISH",
#         "file_1, file_2",
#     )
#     monkeypatch.setenv(
#         "DOCKER_AUTH_FILE_PUBLISH",
#         "file_1, file_2",
#     )

#     # set the attributes
#     monkeypatch.setattr(upload_to_harbor, "promote_tags", lambda a, b, c: True)
#     monkeypatch.setattr(
#         MockSkopeo, "copy", lambda *args, **kwargs: ("file_1", "file_2")
#     )
#     # monkeypatch.setattr(MockPath, "exists", lambda: True)

#     staging_image = Image(
#         registry="REGISTRY_PRE_PUBLISH_URL",
#         name="IMAGE_NAME",
#         digest="IMAGE_PODMAN_SHA",
#         transport="docker://",
#         tag="TAG_1",
#     )
#     production_image = Image(
#         registry="REGISTRY_PRE_PUBLISH_URL",
#         name="IMAGE_NAME_2",
#         digest="IMAGE_PODMAN_SHA",
#         transport="docker://",
#         tag="TAG_2",
#     )

#     upload_to_harbor.promote_tags(
#         staging_image,
#         production_image,
#         ["TAG_1", "TAG_2"],
#     )
#     print(caplog.text)
#     log.info(caplog.text)
#     assert "Copy from staging to IMAGE_NAME" in caplog.text
#     assert "Copy from staging to IMAGE_NAME_2" in caplog.text


# def test_generate_attestation_predicates(monkeypatch):


# @patch("upload_to_harbor.json", new=MockJson)
# @patch("upload_to_harbor.Path", new=MockPath)
# @patch("stages.harbor.upload_to_harbor.json", new=MockJson)
# def test_generate_vat_response_lineage_file(monkeypatch, caplog):
#     monkeypatch.setenv("VAT_RESPONSE", "mock_dir")
#     monkeypatch.setenv("CI_PROJECT_DIR", "mock_dir")
#     monkeypatch.setenv("ACCESS_LOG_DIR", "mock_dir")
#     monkeypatch.setenv("PARENT_VAT_RESPONSE", "mock_dir")
#     monkeypatch.setenv("ARTIFACT_DIR", "mock_dir")

#     monkeypatch.setattr(upload_to_harbor, "pipeline_vat_response", lambda a: MockJson)
#     assert "Dump VAT to file" in caplog.text

#     monkeypatch.delenv("VAT_RESPONSE", "mock_dir")

#     monkeypatch.setattr(upload_to_harbor, "lineage_vat_response", lambda a, b: [])
#     monkeypatch.setattr(
#         upload_to_harbor.open, "parent_vat_response_file", lambda a, b: []
#     )

#     assert "Generated VAT response lineage file" in caplog.text


@patch("upload_to_harbor.json", new=MockJson)
@patch("upload_to_harbor.Path", new=MockPath)
def test_generate_attestation_predicates(monkeypatch):
    monkeypatch.setenv("CI_PROJECT_DIR", "mock_dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "mock_dir")
    monkeypatch.setenv("SBOM_DIR", "mock_dir")

    monkeypatch.setattr(MockPath, "exists", lambda x: True)
    ci_project_dir_files = ["file1.txt", "file2.txt"]
    monkeypatch.setattr(
        os,
        "listdir",
        lambda path: ci_project_dir_files
        if path == os.environ["CI_PROJECT_DIR"]
        else [],
    )

    sbom_dir_files = ["sbom_file1.txt", "sbom_file2.txt"]
    monkeypatch.setattr(
        os,
        "listdir",
        lambda path: sbom_dir_files if path == os.environ["SBOM_DIR"] else [],
    )

    monkeypatch.setattr(os, "listdir", lambda a: [])

    monkeypatch.setattr(
        upload_to_harbor,
        "_convert_artifacts_to_hardening_manifest",
        lambda a, b: None,
    )
    monkeypatch.setattr(
        upload_to_harbor,
        "_generate_vat_response_lineage_file",
        lambda: None,
    )

    predicates = Predicates()
    attestation_predicates = upload_to_harbor.generate_attestation_predicates(
        predicates
    )

    _generate_vat_response_lineage_file = (
        upload_to_harbor.generate_attestation_predicates(predicates)
    )

    # predicates = upload_to_harbor._generate_vat_response_lineage_file(
    #     predicates=Predicates
    # )

    # log.info(predicates)

    assert upload_to_harbor.attestation_predicates(pathlib.Path("some_path")) is None
    # assert upload_to_harbor.attestation_predicates(pathlib.Path("some_path")) is None

    monkeypatch.delenv("CI_PROJECT_DIR", "mock_dir")
    monkeypatch.delenv("ACCESS_LOG_DIR", "mock_dir")
    monkeypatch.delenv("SBOM_DIR", "mock_dir")


# @patch("stages.harbor.upload_to_harbor.json", new=MockJson)
# @patch("upload_to_harbor.Path", new=MockPath)
# def test_convert_artifacts_to_hardening_manifest(monkeypatch):
#     # set env
#     monkeypatch.setenv("CI_PROJECT_DIR", "hardening_manifest.yaml")

#     # set attributes
#     # monkeypatch.setattr(upload_to_harbor, "safe_load", lambda a: None)
#     monkeypatch.setattr(MockPath, "exists", lambda x: True)
#     predicates = Predicates()

#     upload_to_harbor._convert_artifacts_to_hardening_manifest(
#         predicates, MockPath("mock/path", {mock: "data"})
#     )
