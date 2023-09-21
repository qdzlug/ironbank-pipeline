#!/usr/bin/env python3

import os
import yaml
import sys
import json
from pathlib import Path
import pytest
import shutil

from unittest.mock import patch
from pipeline.container_tools.container_tool import ContainerTool
from pipeline.utils.exceptions import GenericSubprocessError
from common.utils import logger
from pipeline.test.mocks.mock_classes import (
    MockImage,
    MockSkopeo,
    MockProject,
    MockHardeningManifest,
    MockPath,
    MockOpen,
    MockOutput,
)

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import upload_to_harbor

log = logger.setup("test_upload_to_harbor")

mock_image = MockImage(
    registry="example.com",
    name="example/test",
    digest="abcd1234",
    tag="1.0",
    transport="docker://",
)


## Extension classes
class MockCosign(ContainerTool):
    def attest(*args, **kwargs):
        return None

    def sign(*args, **kwargs):
        return None


class MockPathExtension(MockPath):
    st_size = 1
    unattached_predicates = []
    name = "vat_response_lineage.json"

    def open(self, mode, encoding="", errors=""):
        return MockOpen()

    def __str__(self):
        return self.name


@patch("upload_to_harbor.Skopeo", new=MockSkopeo)
def test_compare_digests(monkeypatch):
    log.info("Testing the inspection of image from registry")

    monkeypatch.setenv(
        "IMAGE_PODMAN_SHA",
        "sha256:fab00486b9e63e0de51bc706d2893bd1125eb20ad7facb332cf1b69adcbbb71d",
    )
    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/docker_auth_file")
    log.info("Test digests match.")
    upload_to_harbor.compare_digests(mock_image)

    log.info("Testing that function exits as expected when digests don't match.")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "sha256:nomatch")
    with pytest.raises(SystemExit):
        upload_to_harbor.compare_digests(mock_image)


@patch("upload_to_harbor.Skopeo", new=MockSkopeo)
def test_promote_tags(monkeypatch, caplog):
    log.info("Test successful promotion of staging project to prod.")
    staging_image = mock_image.from_image()
    tags = ["tag1", "tag2", "tag3"]
    production_image = MockImage(
        registry="production",
        name="prod/example",
        tag=tags[0],
        transport="artifactory://",
    )

    monkeypatch.setenv("DOCKER_AUTH_FILE_PRE_PUBLISH", "/path/to/staging_auth_file")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PUBLISH", "/path/to/production_auth_file")

    upload_to_harbor.promote_tags(staging_image, production_image, tags)
    assert f"Successfully copied {staging_image} to {production_image}" in caplog.text


@patch("upload_to_harbor.Path", new=MockPathExtension)
def test_convert_artifacts_to_hardening_manifest(monkeypatch, caplog):
    monkeypatch.setattr(MockPathExtension, "name", "test")
    predicate_list = [MockPathExtension("test1"), MockPathExtension("test2")]
    monkeypatch.setenv("CI_PROJECT_DIR", "test_directory")
    monkeypatch.setattr(json, "dump", lambda *args, **kwargs: MockOutput)
    monkeypatch.setattr(
        yaml,
        "safe_load",
        lambda *args, **kwargs: {"test1": "This is test1", "test2": "This is test2"},
    )
    upload_to_harbor._convert_artifacts_to_hardening_manifest(
        predicate_list, MockPathExtension("test")
    )

    assert f"Converting artifacts to hardening manifest" in caplog.text


@patch("upload_to_harbor.Path", new=MockPath)
def test_generate_vat_response_lineage_file(monkeypatch, caplog):
    # Set up test environment
    monkeypatch.setenv("VAT_RESPONSE", "test_vat_response.json")
    monkeypatch.setenv("PARENT_VAT_RESPONSE", "test_parent_vat_response.json")
    monkeypatch.setenv("ARTIFACT_DIR", "test_artifact_dir")
    monkeypatch.setattr(json, "load", lambda *args, **kwargs: {"images": "testing"})
    monkeypatch.setattr(json, "dump", lambda *args, **kwargs: MockOutput)
    result = upload_to_harbor._generate_vat_response_lineage_file()
    assert f"parent VAT" not in caplog.text
    assert result == MockPath("test_artifact_dir/vat_response_lineage.json")

    log.info("Mock testing when parent_vat_response exists")
    monkeypatch.setattr(MockPath, "exists", lambda *args, **kwargs: True)
    result = upload_to_harbor._generate_vat_response_lineage_file()
    assert f"parent VAT" in caplog.text
    caplog.clear()


@patch("upload_to_harbor.Path", new=MockPathExtension)
def test_generate_attestation_predicates(monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", "test_artifact_dir")
    # Set environment variables for testing
    monkeypatch.setenv("CI_PROJECT_DIR", "test_directory")
    monkeypatch.setenv("SBOM_DIR", "sbom_dir")
    monkeypatch.setenv("ACCESS_LOG_DIR", "access_log_dir")
    monkeypatch.setenv("VAT_RESPONSE", "test_vat_response.json")
    monkeypatch.setenv("PARENT_VAT_RESPONSE", "test_parent_vat_response.json")
    monkeypatch.setattr(
        upload_to_harbor,
        "_convert_artifacts_to_hardening_manifest",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        upload_to_harbor,
        "_generate_vat_response_lineage_file",
        lambda *args, **kwargs: MockPathExtension("testing"),
    )
    monkeypatch.setattr(os, "listdir", lambda *args, **kwargs: ["file1", "file2"])
    mock_path_extension = MockPathExtension(".")
    monkeypatch.setattr(os, "stat", lambda *args, **kwargs: mock_path_extension)
    result = upload_to_harbor.generate_attestation_predicates(mock_path_extension)

    assert (
        MockPathExtension("test_directory")
        and MockPathExtension("sbom_dir/file2") in result
    )

    mock_path_extension.unattached_predicates = ["file2"]
    result = upload_to_harbor.generate_attestation_predicates(mock_path_extension)

    assert MockPathExtension("sbom_dir/file2") not in result


@patch("upload_to_harbor.Image", new=MockImage)
@patch("upload_to_harbor.DsopProject", new=MockProject)
@patch("upload_to_harbor.Cosign", new=MockCosign)
@patch("upload_to_harbor.HardeningManifest", new=MockHardeningManifest)
@patch("upload_to_harbor.Path", new=MockPath)
def test_main(monkeypatch, caplog, raise_):
    monkeypatch.setenv("REGISTRY_PRE_PUBLISH_URL", "mock_REGISTRY_PRE_PUBLISH_URL")
    monkeypatch.setenv("IMAGE_NAME", "mock_IMAGE_NAME")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "mock_IMAGE_PODMAN_SHA")
    monkeypatch.setenv("REGISTRY_PUBLISH_URL", "mock_REGISTRY_PUBLISH_URL")
    monkeypatch.setenv("DIGEST_TO_SCAN", "mock_DIGEST_TO_SCAN")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PUBLISH", "mock_DOCKER_AUTH_FILE_PUBLISH")
    monkeypatch.setenv("IMAGE_TO_SCAN", "mock_IMAGE_TO_SCAN")

    monkeypatch.setattr(
        upload_to_harbor, "compare_digests", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        upload_to_harbor,
        "generate_attestation_predicates",
        lambda *args, **kwargs: [
            MockPathExtension("test1"),
            MockPathExtension("test2"),
        ],
    )
    monkeypatch.setattr(shutil, "copy", lambda *args, **kwargs: None)

    upload_to_harbor.main()
    assert "Adding attestations" in caplog.text

    monkeypatch.setenv("IMAGE_TO_SCAN", "ironbank-staging")
    monkeypatch.setattr(upload_to_harbor, "promote_tags", lambda *args, **kwargs: None)
    upload_to_harbor.main()
    assert "Promoting images and tags from staging" in caplog.text

    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            upload_to_harbor,
            "compare_digests",
            lambda *args, **kwargs: raise_(GenericSubprocessError),
        )
        upload_to_harbor.main()


@patch("upload_to_harbor.Image", new=MockImage)
@patch("upload_to_harbor.Cosign", new=MockCosign)
@patch("upload_to_harbor.Path", new=MockPathExtension)
@patch(
    "upload_to_harbor._generate_vat_response_lineage_file",
    return_value=MockPathExtension("test_vat_response.json"),
)
@patch("shutil.copy")
def test_publish_vat_staging_predicates(
    mock_copy, mock_vat_response_lineage_file, monkeypatch
):
    # Mocking necessary environment variables
    monkeypatch.setenv("REGISTRY_PRE_PUBLISH_URL", "mock_REGISTRY_PRE_PUBLISH_URL")
    monkeypatch.setenv("IMAGE_NAME", "mock_IMAGE_NAME")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "mock_IMAGE_PODMAN_SHA")
    monkeypatch.setenv(
        "DOCKER_AUTH_FILE_PRE_PUBLISH", "mock_DOCKER_AUTH_FILE_PRE_PUBLISH"
    )

    # Call the function
    upload_to_harbor.publish_vat_staging_predicates()

    # Assertions
    expected_path = MockPathExtension("config.json")

    # Get the actual arguments passed to mock_copy
    actual_args = mock_copy.call_args[
        0
    ]  # Extract the positional arguments used in the mock call

    # Ensure the arguments match what we expect
    assert str(actual_args[0]) == "mock_DOCKER_AUTH_FILE_PRE_PUBLISH"
    assert str(actual_args[1]) == str(expected_path)

    # Testing GenericSubprocessError exception
    with patch("upload_to_harbor.Cosign.attest", side_effect=GenericSubprocessError):
        with pytest.raises(SystemExit) as excinfo:
            upload_to_harbor.publish_vat_staging_predicates()
        assert excinfo.value.code == 1
