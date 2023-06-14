#!/usr/bin/env python3

import asyncio
import os
import shutil
import sys
from unittest.mock import patch

import pytest

from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockJson,
    MockPath,
    MockSkopeo,
)
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import GenericSubprocessError

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import base_image_validation  # noqa E402

log = logger.setup("test_base_image_validation")


@patch("base_image_validation.Skopeo", new=MockSkopeo)
@patch("base_image_validation.HardeningManifest", new=MockHardeningManifest)
@patch("base_image_validation.Path", new=MockPath)
@patch("base_image_validation.json", new=MockJson)
def test_base_image_validation_main(monkeypatch, caplog, raise_):
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

    asyncio.run(base_image_validation.main())
    assert "Dump SHA to file" in caplog.text

    monkeypatch.delenv("STAGING_BASE_IMAGE")
    monkeypatch.delenv("DOCKER_AUTH_FILE_PRE_PUBLISH")
    monkeypatch.delenv("REGISTRY_PRE_PUBLISH_URL")

    log.info("Test prod base image validation")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "test")
    monkeypatch.setenv("BASE_REGISTRY", "http://prod.com")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwer"}
    )
    asyncio.run(base_image_validation.main())
    assert "Dump SHA to file" in caplog.text

    log.info("Test cosign verify fails")
    monkeypatch.setattr(
        base_image_validation.Cosign, "verify", lambda *args, **kwargs: False
    )
    with pytest.raises(SystemExit) as e:
        asyncio.run(base_image_validation.main())
    assert e.value.code == 1

    log.info("Test base image validation throws exception")
    monkeypatch.setattr(
        base_image_validation.Cosign, "verify", lambda *args, **kwargs: True
    )
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    with pytest.raises(SystemExit) as e:
        asyncio.run(base_image_validation.main())
    assert e.value.code == 1
