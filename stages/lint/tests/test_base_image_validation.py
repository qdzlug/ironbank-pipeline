#!/usr/bin/env python3

import sys
import os
from unittest.mock import patch
import pytest
import asyncio
from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockSkopeo,
    MockPath,
    MockJson,
)
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.utils import logger

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import base_image_validation  # noqa E402

log = logger.setup("test_base_image_validation")


@patch("base_image_validation.Skopeo", new=MockSkopeo)
@patch("base_image_validation.HardeningManifest", new=MockHardeningManifest)
@patch("base_image_validation.Path", new=MockPath)
@patch("base_image_validation.json", new=MockJson)
def test_base_image_validation_main(monkeypatch, caplog):
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

    log.info("Test base image validation throws exception")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    with pytest.raises(SystemExit) as se:
        asyncio.run(base_image_validation.main())
    assert se.value.code == 1
