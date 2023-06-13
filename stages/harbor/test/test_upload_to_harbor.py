#!/usr/bin/env python3

import asyncio
import hashlib
import os
import pytest
from pathlib import Path
import sys
from unittest import mock
import base64
import json
from requests import patch
from ironbank.pipeline.test.mocks.mock_classes import MockPath, MockSkopeo
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
# def mock_digest():


@patch("upload_to_harbor.Skopeo", new=MockSkopeo)
@patch("upload_to_harbor.Path", new=MockPath)
def test_compare_digests(monkeypatch):
    # Mock the necessary environment variables
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_file_path")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "mock_our_image_podman_sha")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_skopeo")

    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwer"}
    )

    asyncio.run(compare_digests)
    assert "Pulling manifest_file with skopeo" in caplog.text

    monkeypatch.delenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_skopeo")

    monkeypatch.setattr(upload_to_harbor, "hashlib.sha256", lambda a: [])
    monkeypatch.setattr(upload_to_harbor, "remote_inspect_raw", lambda a: None)

    # Mock the log functions
    mock_log = Mock()

    # Mock the hashlib.sha256 function
    mock_sha256 = Mock()
    mock_sha256.return_value.hexdigest.return_value = "computed_digest"

    # Define the input image
    image = Mock()
    image.from_image.return_value = "docker_image"

    # Call the function under test
    compare_digests(image)

    # Assert that the necessary methods were called with the expected arguments
    mock_log.info.assert_called_with("Pulling manifest_file with skopeo")
    mock_skopeo.assert_called_with(Path("docker://"))
    mock_skopeo.inspect.assert_called_with("docker_image", raw=True, log_cmd=True)
    mock_sha256.assert_called_with(b"remote_inspect_raw")
    mock_log.error.assert_not_called()
    sys.exit.assert_not_called()

    # Assert the expected log message for matching digests
    mock_log.info.assert_any_call("Digests match")

    # Reset the mocked sys.exit function
    sys.exit.reset_mock()

    # Modify the environment variable to simulate mismatched digests
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "different_digest")

    # Call the function under test again
    compare_digests(image)

    # Assert the expected log message and sys.exit call for mismatched digests
    mock_log.error.assert_called_with(
        "Digests do not match your_image_podman_sha  computed_digest"
    )
    sys.exit.assert_called_with(1)


@patch("upload_to_harbor.json", new=MockJson)
@patch("upload_to_harbor.Path", new=MockPath)
# @patch("stages.harbor.upload_to_harbor.json", new=MockJson)
def test_generate_vat_response_lineage_file(
    caplog,
    monkeypatch,
    mock_pipeline_vat_response,
    mock_pipeline_parent_vat_response,
    mock_hm_content,
):
    monkeypatch.setenv("VAT_RESPONSE", "mock_dir")
    monkeypatch.setenv("CI_PROJECT_DIR", "mock_dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "mock_dir")
    monkeypatch.setenv("PARENT_VAT_RESPONSE", "mock_dir")
    monkeypatch.setenv("ARTIFACT_DIR", "mock_dir")

    upload_to_harbor._generate_vat_response_lineage_file()
    assert "Generated VAT response lineage file" in caplog.text


# @patch("upload_to_harbor.json", new=MockJson)
# @patch("upload_to_harbor.Path", new=MockPath)
# def test_generate_attestation_predicates(monkeypatch):
#     monkeypatch.setenv("CI_PROJECT_DIR", "mock_dir")
#     monkeypatch.setenv("ACCESS_LOG_DIR", "mock_dir")
#     monkeypatch.setenv("SBOM_DIR", "mock_dir")

#     mock_result = ["LICENSE", "README.md", "access_log"]

#     monkeypatch.setattr(
#         os,
#         "listdir",
#         lambda path: mock_result if path == os.environ["CI_PROJECT_DIR"] else [],
#     )

#     monkeypatch.setattr(os, "listdir", lambda a: [])

#     monkeypatch.setattr(
#         upload_to_harbor,
#         "_convert_artifacts_to_hardening_manifest",
#         lambda a, b: None,
#     )

#     predicates = Predicates()
#     upload_to_harbor.generate_attestation_predicates(predicates)

#     predicates = [
#         Path(os.environ["SBOM_DIR"], file)
#         for file in os.listdir(os.environ["SBOM_DIR"])
#         if file not in predicates.unattached_predicates
#     ]

#     predicates.append(Path(os.environ["CI_PROJECT_DIR"], "hardening_manifest.json"))
#     predicates.append(_generate_vat_response_lineage_file())

#     assert predicates == expected_predicates
