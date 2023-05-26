#!/usr/bin/env python3

import pytest
from unittest.mock import patch


# Import the module under test
from ironbank.pipeline import upload_to_harbor

def test_compare_digests(monkeypatch):
    # Mock the necessary environment variables
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "image_digest")

    # Patch the Skopeo class and its methods
    mock_inspect = "remote_inspect_raw"
    mock_skopeo = patch.object(upload_to_harbor.Skopeo, "inspect", return_value=mock_inspect)
    monkeypatch.setattr(upload_to_harbor, "Skopeo", mock_skopeo)

    # Patch the logger
    mock_info = patch.object(upload_to_harbor.log, "info")
    mock_error = patch.object(upload_to_harbor.log, "error")
    monkeypatch.setattr(upload_to_harbor.log, "info", mock_info)
    monkeypatch.setattr(upload_to_harbor.log, "error", mock_error)

    # Call the function under test
    staging_image = upload_to_harbor.Image()
    upload_to_harbor.compare_digests(staging_image)

    # Assertions
    mock_skopeo.inspect.assert_called_once_with(
        staging_image.from_image(transport="docker://"),
        raw=True,
        log_cmd=True
    )
    mock_info.assert_called_with("Pulling manifest_file with skopeo")
    mock_info.assert_called_with("Inspecting image in registry")
    mock_error.assert_not_called()
    assert mock_info.call_count == 2

def test_promote_tags(monkeypatch):
    # Mock the necessary environment variables
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/auth_file")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PUBLISH", "/path/to/auth_file")

    # Patch the Skopeo class and its methods
    mock_copy = patch.object(upload_to_harbor.Skopeo, "copy")
    monkeypatch.setattr(upload_to_harbor, "Skopeo.copy", mock_copy)

    # Patch the logger
    mock_info = patch.object(upload_to_harbor.log, "info")
    monkeypatch.setattr(upload_to_harbor.log, "info", mock_info)

    # Call the function under test
    staging_image = upload_to_harbor.Image()
    production_image = upload_to_harbor.Image()
    tags = ["tag1", "tag2"]
    upload_to_harbor.promote_tags(staging_image, production_image, tags)

    # Assertions
    assert mock_info.call_count == 3
    mock_copy.assert_called_once_with(
        staging_image,
        production_image.from_image(tag="tag2"),
        src_authfile="/path/to/auth_file",
        dest_authfile="/path/to/auth_file",
        log_cmd=True
    )

def test_generate_attestation_predicates(monkeypatch, tmp_path):
    # Mock the necessary environment variables
    monkeypatch.setenv("CI_PROJECT_DIR", "/path/to/project_dir")
    monkeypatch.setenv("SBOM_DIR", "/path/to/sbom_dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "/path/to/access_log_dir")

    # Create temporary files
    predicate_file1 = tmp_path / "predicate1.txt"
    predicate_file1.write_text("predicate1 content")
    predicate_file2 = tmp_path / "predicate2.txt"
    predicate2_content = "predicate2 content"
    predicate_file2.write_text(predicate2_content)

    # Patch
