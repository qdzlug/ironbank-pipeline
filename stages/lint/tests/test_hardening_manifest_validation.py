#!/usr/bin/env python3

import sys
import asyncio
import os
import pytest
import pathlib
from unittest.mock import patch
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockProject,
    MockHardeningManifest,
    MockPath
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hardening_manifest_validation  # noqa E402

log = logger.setup("test_hardening_manifest_validation")


@patch("hardening_manifest_validation.DsopProject", new=MockProject)
@patch("hardening_manifest_validation.HardeningManifest", new=MockHardeningManifest)
def test_hardening_manifest_validation_main(monkeypatch, caplog):

    log.info("Test successful valiation")
    monkeypatch.setenv("ARTIFACT_DIR", MockPath)
    monkeypatch.setattr(HardeningManifest, "create_artifacts", lambda x: x)
    asyncio.run(hardening_manifest_validation.main())
    assert "Hardening manifest is validated" in caplog.text

    log.info("Test invalid image sources")
    monkeypatch.setattr(
        MockHardeningManifest, "invalid_image_sources", "bad_image_source"
    )
    with pytest.raises(SystemExit) as se:
        asyncio.run(hardening_manifest_validation.main())
    assert se.value.code == 100

    log.info("Test invalid labels")
    monkeypatch.setattr(MockHardeningManifest, "invalid_labels", "bad_label")
    with pytest.raises(SystemExit) as se:
        asyncio.run(hardening_manifest_validation.main())
    assert se.value.code == 1

    log.info("Test invalid maintainers")
    monkeypatch.setattr(MockHardeningManifest, "invalid_maintainers", "bad_maintainer")
    with pytest.raises(SystemExit) as se:
        asyncio.run(hardening_manifest_validation.main())
    assert se.value.code == 1
