#!/usr/bin/env python3

import pathlib
import sys
import os
from unittest.mock import patch
import pytest
import asyncio
from ironbank.pipeline.test.mocks.mock_classes import (
    MockProject,
    MockHardeningManifest,
    MockSkopeo,
)
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.utils import logger

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import base_image_validation  # noqa E402

log = logger.setup("test_base_image_validation")

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent.parent,
    "ironbank/pipeline/test/mocks",
)


@patch("base_image_validation.DsopProject", new=MockProject)
@patch("base_image_validation.Skopeo", new=MockSkopeo)
@patch("base_image_validation.HardeningManifest", new=MockHardeningManifest)
def test_base_image_validation_main(monkeypatch):

    log.info("Test staging base image validation")
    monkeypatch.setenv("STAGING_BASE_IMAGE", "base")
    monkeypatch.setenv(
        "DOCKER_AUTH_CONFIG_STAGING", "c3RhZ2luZy10ZXN0Cg=="
    )  # staging-test -> base64 encoded value
    monkeypatch.setenv("REGISTRY_URL_STAGING", "http://staging.com")
    monkeypatch.setenv("ARTIFACT_DIR", mock_path)
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwer"}
    )
    with open(mock_path/"base_image.json", "w"):
        pass
    asyncio.run(base_image_validation.main())
    os.remove(mock_path/"base_image.json")

    monkeypatch.delenv("STAGING_BASE_IMAGE")
    monkeypatch.delenv("DOCKER_AUTH_CONFIG_STAGING")
    monkeypatch.delenv("REGISTRY_URL_STAGING")

    log.info("Test prod base image validation")
    monkeypatch.setenv("DOCKER_AUTH_CONFIG_PULL", "c3RhZ2luZy10ZXN0Cg==")
    monkeypatch.setenv("REGISTRY_URL_PROD", "http://prod.com")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: {"Digest": "1234qwer"}
    )
    with open(mock_path/"base_image.json", "w"):
        pass
    asyncio.run(base_image_validation.main())
    os.remove(mock_path/"base_image.json")

    log.info("Test base image validation throws exception")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    with pytest.raises(SystemExit) as se:
        asyncio.run(base_image_validation.main())
    assert se.value.code == 1
