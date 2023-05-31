#!/usr/bin/env python3

import os
from pathlib import Path
from unittest import mock

import pytest

from stages.harbor.upload_to_harbor import generate_attestation_predicates

@pytest.fixture
def mock_environ(monkeypatch):
    monkeypatch.setenv("CI_PROJECT_DIR", "/path/to/project_dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "/path/to/access_log_dir")
    monkeypatch.setenv("SBOM_DIR", "/path/to/sbom_dir")


def test_generate_attestation_predicates(mock_environ, monkeypatch, tmp_path):
    mock_listdir = mock.Mock(return_value=["file1.txt", "file2.txt"])
    monkeypatch.setattr("os.listdir", mock_listdir)

    predicates = mock.Mock(unattached_predicates=["file2.txt"])

    mock_convert_artifacts = mock.Mock()
    monkeypatch.setattr("stages.harbor.upload_to_harbor._convert_artifacts_to_hardening_manifest", mock_convert_artifacts)

    mock_generate_vat_response_lineage = mock.Mock(return_value="vat_response_lineage_file")
    monkeypatch.setattr("stages.harbor.upload_to_harbor._generate_vat_response_lineage_file", mock_generate_vat_response_lineage)

    attestation_predicates = generate_attestation_predicates(predicates)

    assert attestation_predicates == [
        Path("SBOM_DIR", "file1.txt"),
        Path("CI_PROJECT_DIR", "hardening_manifest.json"),
        "vat_response_lineage_file"
    ]

    mock_listdir.assert_called_with("SBOM_DIR")
    mock_convert_artifacts.assert_called_with(
        [Path("CI_PROJECT_DIR", "LICENSE"), Path("CI_PROJECT_DIR", "README.md")],
        Path("CI_PROJECT_DIR", "hardening_manifest.yaml"),
    )
    mock_generate_vat_response_lineage.assert_called_once()


# def test_compare_digests(monkeypatch):
#     # Mock the necessary environment variables
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
#     monkeypatch.setenv("IMAGE_PODMAN_SHA", "image_digest")
#     # 
#     # Patch the Skopeo class and its methods
#     mock_inspect = "remote_inspect_raw"
    # mock_skopeo = patch.object(upload_to_harbor.Skopeo, "inspect", return_value=mock_inspect)
    
    # # Patch the logger
    # mock_info = patch.object(upload_to_harbor.log, "info")
    # mock_error = patch.object(upload_to_harbor.log, "error")

    # monkeypatch.setattr(upload_to_harbor.log, "info", mock_info)
    # monkeypatch.setattr(upload_to_harbor.log, "error", mock_error)
    # monkeypatch.setattr(upload_to_harbor, "Skopeo", mock_skopeo)

    # # Call the function under test
    # staging_image = upload_to_harbor.Image()
    # upload_to_harbor.compare_digests(staging_image)

    # # Assertions
    # mock_skopeo.inspect.assert_called_once_with(
    #     staging_image.from_image(transport="docker://"),
    #     raw=True,
    #     log_cmd=True
    # )
    # mock_info.assert_called_with("Pulling manifest_file with skopeo")
    # mock_info.assert_called_with("Inspecting image in registry")
    # mock_error.assert_not_called()
    # assert mock_info.call_count == 2

# def test_promote_tags(monkeypatch: MonkeyPatch):
#     # Mock the necessary environment variables
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
#     monkeypatch.setenv("DOCKER_AUTH_FILE_PUBLISH", "/path/to/auth_file")

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
#         src_authfile="/path/to/auth_file",
#         dest_authfile="/path/to/auth_file",
#         log_cmd=True
#     )

# @pytest.fixture
# def mock_environ(monkeypatch: MonkeyPatch):
#     monkeypatch.setenv("CI_PROJECT_DIR", "/path/to/project_dir")
#     monkeypatch.setenv("ACCESS_LOG_DIR", "/path/to/access_log_dir")
#     monkeypatch.setenv("SBOM_DIR", "/path/to/sbom_dir")


# def test_generate_attestation_predicates(mock_environ: None, monkeypatch: MonkeyPatch, tmp_path: Path):
#     mock_listdir = mock.Mock(return_value=["file1.txt", "file2.txt"])
#     monkeypatch.setattr("os.listdir", mock_listdir)

#     predicates = mock.Mock(unattached_predicates=["file2.txt"])

#     mock_convert_artifacts = mock.Mock()
#     monkeypatch.setattr("your_module._convert_artifacts_to_hardening_manifest", mock_convert_artifacts)

#     mock_generate_vat_response_lineage = mock.Mock(return_value="vat_response_lineage_file")
#     monkeypatch.setattr("your_module._generate_vat_response_lineage_file", mock_generate_vat_response_lineage)

#     attestation_predicates = generate_attestation_predicates(predicates)

#     assert attestation_predicates == [
#         Path("/path/to/sbom_dir", "file1.txt"),
#         Path("/path/to/project_dir", "hardening_manifest.json"),
#         "vat_response_lineage_file"
#     ]

#     mock_listdir.assert_called_with("/path/to/sbom_dir")
#     mock_convert_artifacts.assert_called_with(
#         [Path("/path/to/project_dir", "LICENSE"), Path("/path/to/project_dir", "README.md")],
#         Path("/path/to/project_dir", "hardening_manifest.yaml"),
#     )
#     mock_generate_vat_response_lineage.assert_called_once()