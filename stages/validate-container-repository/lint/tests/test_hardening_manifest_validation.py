#!/usr/bin/env python3

import asyncio
import sys
from unittest.mock import patch
from pathlib import Path

import pytest

from pipeline.hardening_manifest import HardeningManifest
from pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockPath,
    MockProject,
)
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
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

    log.info("Test invalid labels")
    monkeypatch.setattr(MockHardeningManifest, "invalid_labels", "bad_label")
    with pytest.raises(SystemExit) as e:
        asyncio.run(hardening_manifest_validation.main())
    assert e.value.code == 1

    log.info("Test invalid maintainers")
    monkeypatch.setattr(MockHardeningManifest, "invalid_maintainers", "bad_maintainer")
    with pytest.raises(SystemExit) as e:
        asyncio.run(hardening_manifest_validation.main())
    assert e.value.code == 1

    log.info("Test invalid member advocates")
    monkeypatch.setattr(
        MockHardeningManifest, "invalid_partner_advocates", "bad_partner_advocates"
    )
    with pytest.raises(SystemExit) as e:
        asyncio.run(hardening_manifest_validation.main())
    assert e.value.code == 1


@patch("hardening_manifest_validation.HardeningManifest", new=MockHardeningManifest)
def test_hardening_manifest_architecture_validation(monkeypatch, caplog):
    monkeypatch.setattr(HardeningManifest, "create_artifacts", lambda x: x)

    # Architecture is arm64
    log.info("Should be validated when architecture key is set")
    assert MockHardeningManifest.architecture == ["arm64"]
    asyncio.run(hardening_manifest_validation.main())
    assert "Hardening manifest is validated" in caplog.text
    assert MockHardeningManifest.architecture == ["arm64"]

    # Architecture is set to both values
    monkeypatch.setattr(MockHardeningManifest, "architecture", ["arm64", "x86"])
    asyncio.run(hardening_manifest_validation.main())
    assert "Hardening manifest is validated" in caplog.text
    assert MockHardeningManifest.architecture == ["arm64", "x86"]

    # Architecture is None
    monkeypatch.setattr(MockHardeningManifest, "architecture", None)
    asyncio.run(hardening_manifest_validation.main())
    assert "Hardening manifest is validated" in caplog.text
    assert MockHardeningManifest.architecture == None
