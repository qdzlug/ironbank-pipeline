#!/usr/bin/env python3

import asyncio
import os
import pytest
from pathlib import Path
import sys
from unittest import mock
import base64
import json
from requests import patch
from ironbank.pipeline.test.mocks.mock_classes import MockPath
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
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import upload_to_harbor
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


# @patch.dict(
#     os.environ,
#     {
#         "VAT_RESPONSE": "",
#         "PARENT_VAT_RESPONSE": "",
#         "ARTIFACT_DIR": "",
#         "CI_PROJECT_DIR": "",
#         "ACCESS_LOG_DIR": "",
#     },
# )
# @patch("stages.harbor.upload_to_harbor.Path", new=MockPath)
# # @patch("stages.harbor.upload_to_harbor.json", new=MockJson)
# def test_generate_vat_response_lineage_file(
#     caplog,
#     monkeypatch,
#     mock_pipeline_vat_response,
#     mock_pipeline_parent_vat_response,
#     mock_hm_content,
# ):
#     monkeypatch.setenv("CI_PROJECT_DIR", "dir")
#     monkeypatch.setenv("ACCESS_LOG_DIR", "dir")

#     mock_output_dir = MockPath("./example")
#     mock_docker_conf_dir = MockPath("./")

#     monkeypatch.setattr(
#         subprocess,
#         "Popen",
#         lambda *args, **kwargs: MockPopen(
#             stdout=MockOutput(mock_data="{}"), poll_counter=0, returncode=1
#         ),
#     )
#     monkeypatch.setattr(json, "loads", lambda x: x)
#     monkeypatch.setattr(base64, "b64decode", lambda x: x)

#     result = upload_to_harbor._generate_vat_response_lineage_file()

# monkeypatch.setattr(
#     pathlib.Path, "open", mock_open(read_data=yaml.safe_dump(mock_hm_content))
# )

# monkeypatch.setattr(
#     pathlib.Path,
#     "open",
#     mock_open(read_data=json.dumps(mock_pipeline_vat_response)),
# )

# monkeypatch.setattr(
#     pathlib.Path,
#     "open",
#     mock_open(read_data=json.dumps(mock_pipeline_parent_vat_response)),
# )

# predicates = Predicates()
# attestation_predicates = upload_to_harbor.generate_attestation_predicates(
#     predicates
# )

#

# Verify the log message
# assert "Generated VAT response lineage file successfully" in caplog.text


@patch("stages.harbor.upload_to_harbor.Path", new=MockPath)
def test_generate_attestation_predicates(monkeypatch, tmp_path):
    monkeypatch.setenv("CI_PROJECT_DIR", "dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "dir")
    monkeypatch.setattr(
        Path, "_convert_artifacts_to_hardening_manifest", lambda a, b: None
    )
    # staging image is always the new image
    staging_image = Image(
        registry="http://test.url",
        name="test_image",
        digest="test_podman_sha",
        transport="docker://",
    )

    asyncio.run(generate_attestation_predicates.main())
    assert "test image" in caplog.text

    monkeypatch.delenv("CI_PROJECT_DIR")
    monkeypatch.delenv("ACCESS_LOG_DIR")

    monkeypatch.setenv("SBOM_DIR", "file")
    monkeypatch.setenv("CI_CI_PROJECT_DIR", "hardening_manifest.json")
    monkeypatch.setatt(
        attestation_predicates, "attestation_predicates.append", lambda a, b: __file__
    )

    # project = DsopProject()
    # hm = HardeningManifest(project.hardening_manifest_path)

    # predicates = Predicates()
    # attestation_predicates = upload_to_harbor.generate_attestation_predicates(
    #     predicates
    # )


#     # Mocking the environment variables
#     mock_env = {
#         "CI_PROJECT_DIR": "/path/to/project",
#         "ACCESS_LOG_DIR": "/path/to/access_log",
#         "SBOM_DIR": "/path/to/sbom",
#     }
#     with mock.patch.dict(os.environ, mock_env):
#         # Mocking the file list in the SBOM_DIR
#         mock_sbom_files = ["file1.txt", "file2.txt", "file3.txt"]
#         with mock.patch("os.listdir", return_value=mock_sbom_files):
#             # Mocking the predicates object
#             mock_predicates = mock.Mock()
#             mock_predicates.unattached_predicates = ["file2.txt"]

#             # Call the function under test
#     result = generate_attestation_predicates(mock_predicates)
#      # Verify the result
#     expected_result = [
#         Path("/path/to/sbom", "file1.txt"),
#         Path("/path/to/sbom", "file3.txt"),
#         Path("/path/to/project", "hardening_manifest.json"),
#         _generate_vat_response_lineage_file(),
#     ]
#     assert result == expected_result

#     # Verify the log message
#     assert "Generated attestation predicates successfully" in caplog.text
#     assert "Error occurred" not in caplog.text


# unattached_predicates = ["file3.txt", "file4.txt"]

# assertions
# asyncio.run(generate_attestation_predicates.main())
# assert "file3.text" in caplog.text
# assert "file4.text" in caplog.text
# caplog.clear()

# with pytest.raises(SystemExit) as se:
#     asyncio.run(generate_attestation_predicates.main())
# assert se.value.code == 1
