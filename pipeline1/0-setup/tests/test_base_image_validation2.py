#!/usr/bin/env python3

import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from common.utils import logger
from pipeline import harbor
from pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockJson,
    MockPath,
    MockSkopeo,
)
from pipeline.utils.exceptions import GenericSubprocessError

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import base_image_validation  # noqa E402

log = logger.setup("test_base_image_validation")


def mock_get_json_for_image_or_manifest_list(hardening_manifest):
    return {"manifest_media_type": "NotAManifest"}


@patch("base_image_validation.Skopeo", new=MockSkopeo)
@patch("base_image_validation.HardeningManifest", new=MockHardeningManifest)
@patch("base_image_validation.Path", new=MockPath)
@patch("base_image_validation.json", new=MockJson)
def test_base_image_validation_main(monkeypatch, caplog, raise_):
    # set required image verification environment variables (for both staging and prod)
    monkeypatch.setenv("KMS_KEY_SHORT_ARN", "kmsKey")
    monkeypatch.setenv("COSIGN_CERT", "cert")
    monkeypatch.setenv("COSIGN_PUBLIC_KEY", "publicKey")
    monkeypatch.setenv("COSIGN_CERTIFICATE_CHAIN", "chain")
    monkeypatch.setenv("BASE_REGISTRY", "prod.com")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "README.md")
    log.info("Test staging base image validation")
    monkeypatch.setenv("STAGING_BASE_IMAGE", "base")
    monkeypatch.setenv(
        "DOCKER_AUTH_FILE_PRE_PUBLISH", "test"
    )  # staging-test -> base64 encoded value
    monkeypatch.setenv("REGISTRY_PRE_PUBLISH_URL", "http://staging.com")
    monkeypatch.setenv("ARTIFACT_DIR", "")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwert"}
    )
    monkeypatch.setattr(shutil, "copy", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        base_image_validation.Cosign, "verify", lambda *args, **kwargs: True
    )

    monkeypatch.setattr(
        harbor,
        "get_json_for_image_or_manifest_list",
        mock_get_json_for_image_or_manifest_list,
    )

    base_image_validation.validate_base_image("amd64")
    assert "Dump SHA to file" in caplog.text

    monkeypatch.delenv("STAGING_BASE_IMAGE")
    monkeypatch.delenv("DOCKER_AUTH_FILE_PRE_PUBLISH")
    monkeypatch.delenv("REGISTRY_PRE_PUBLISH_URL")

    log.info("Test prod base image validation")

    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwer"}
    )
    base_image_validation.validate_base_image("amd64")
    assert "Dump SHA to file" in caplog.text

    log.info("Test cosign verify fails")
    monkeypatch.setattr(
        base_image_validation.Cosign, "verify", lambda *args, **kwargs: False
    )
    with pytest.raises(SystemExit) as e:
        base_image_validation.validate_base_image("amd64")
    assert e.value.code == 1

    log.info("Test base image validation throws exception")
    monkeypatch.setattr(
        base_image_validation.Cosign, "verify", lambda *args, **kwargs: True
    )
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    with pytest.raises(SystemExit) as e:
        base_image_validation.validate_base_image("amd64")
    assert e.value.code == 1
