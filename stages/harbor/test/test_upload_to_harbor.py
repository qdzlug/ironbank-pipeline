#!/usr/bin/env python3

import os
from pathlib import Path
import sys
from unittest import mock

from requests import patch
from ironbank.pipeline.test.mocks.mock_classes import MockPath

# sys.path.append(Path(__file__).parents[2])
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import upload_to_harbor
import pytest

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

# from stages.harbor.upload_to_harbor import generate_attestation_predicates


# def test_compare_digests(monkeypatch):
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
#     monkeypatch.setenv("IMAGE_PODMAN_SHA", "image_digest")

#     # Patch the Skopeo class and its methods
#     mock_inspect = "remote_inspect_raw"
#     mock_skopeo = patch.object(
#         upload_to_harbor.Skopeo, "inspect", return_value=mock_inspect
#     )

#     # Patch the logger
#     mock_info = patch.object(upload_to_harbor.log, "info")
#     mock_error = patch.object(upload_to_harbor.log, "error")

#     monkeypatch.setattr(upload_to_harbor.log, "info", mock_info)
#     monkeypatch.setattr(upload_to_harbor.log, "error", mock_error)
#     monkeypatch.setattr(upload_to_harbor, "Skopeo", mock_skopeo)

#     # Call the function under test
#     staging_image = upload_to_harbor.Image()
#     upload_to_harbor.compare_digests(staging_image)

#     # Assertions
#     mock_skopeo.inspect.assert_called_once_with(
#         staging_image.from_image(transport="docker://"), raw=True, log_cmd=True
#     )
#     mock_info.assert_called_with("Pulling manifest_file with skopeo")
#     mock_info.assert_called_with("Inspecting image in registry")
#     mock_error.assert_not_called()
#     assert mock_info.call_count == 2


# @pytest.fixture
# def mock_environ(monkeypatch):
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PUBLISH", "/path/to/auth_file")


# def test_promote_tags(monkeypatch):
#     # Patch the Skopeo class and its methods
#     mock_copy = patch.object(upload_to_harbor.Skopeo, "copy")
#     monkeypatch.setattr(upload_to_harbor, "Skopeo.copy", mock_copy)

#     # Patch the logger
#     mock_info = patch.object(upload_to_harbor.log, "info")
#     monkeypatch.setattr(upload_to_harbor.log, "info", mock_info)

#     # Call the function under test
#     staging_image = upload_to_harbor.Image()
#     production_image = upload_to_harbor.Image()
#     tags = ["tag1", "tag2"]
#     upload_to_harbor.promote_tags(staging_image, production_image, tags)

#     # Assertions
#     assert mock_info.call_count == 3
#     mock_copy.assert_called_once_with(
#         staging_image,
#         production_image.from_image(tag="tag2"),
#         src_authfile="DOCKER_AUTH_FILE_PRE_PUBLISH",
#         dest_authfile="DOCKER_AUTH_FILE_PUBLISH",
#         log_cmd=True,
#     )


def mock_listdir(path):
    return ["file1.txt", "file2.txt", "file3.txt", "file4.txt"]


@pytest.mark.only
@patch(upload_to_harbor.Path, new=MockPath)
def test_generate_attestation_predicates(mock_environ, monkeypatch, tmp_path):
    monkeypatch.setattr(
        upload_to_harbor, "_convert_artifacts_to_hardening_manifest", lambda a, b: None
    )

    # Mock the environment variables
    sbom_dir = "/mock/sbom/dir"
    monkeypatch.setenv("SBOM_DIR", sbom_dir)

    # Mock the predicates.unattached_predicates list
    unattached_predicates = ["file3.txt", "file4.txt"]
    monkeypatch.setattr(predicates, "unattached_predicates", unattached_predicates)
    # Mock the os.listdir function
    monkeypatch.setattr(os, "listdir", mock_listdir)

    # mock_listdir = mock.Mock(return_value=["file1.txt", "file2.txt"])
    # monkeypatch.setattr("os.listdir", mock_listdir)

    # predicates = mock.Mock(unattached_predicates=["file2.txt"])

    # mock_convert_artifacts = mock.Mock()
    # monkeypatch.setattr("stages.harbor.upload_to_harbor._convert_artifacts_to_hardening_manifest", mock_convert_artifacts)

    # mock_generate_vat_response_lineage = mock.Mock(return_value="vat_response_lineage_file")
    # monkeypatch.setattr("stages.harbor.upload_to_harbor._generate_vat_response_lineage_file", mock_generate_vat_response_lineage)

    # attestation_predicates = generate_attestation_predicates(predicates)

    # assert attestation_predicates == [
    #     Path("SBOM_DIR", "file1.txt"),
    #     Path("CI_PROJECT_DIR", "hardening_manifest.json"),
    #     "vat_response_lineage_file"
    # ]

    # mock_listdir.assert_called_with("SBOM_DIR")
    # mock_convert_artifacts.assert_called_with(
    #     [Path("CI_PROJECT_DIR", "LICENSE"), Path("CI_PROJECT_DIR", "README.md")],
    #     Path("CI_PROJECT_DIR", "hardening_manifest.yaml"),
    # )
    # mock_generate_vat_response_lineage.assert_called_once()
