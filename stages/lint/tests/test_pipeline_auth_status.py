#!/usr/bin/env python3

import os
import sys
import asyncio
import pytest
import pathlib
from unittest.mock import patch
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockProject,
    MockHardeningManifest,
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_auth_status  # noqa E402

log = logger.setup(name="test_pipeline_auth_status")

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent.parent,
    "ironbank/pipeline/test/mocks",
)

@patch("pipeline_auth_status.DsopProject", new=MockProject)
@patch("pipeline_auth_status.HardeningManifest", new=MockHardeningManifest)
def test_pipeline_auth_status_main(monkeypatch, caplog):
    
    log.info("Test successful auth status")
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "http://vat-local.example")
    monkeypatch.setenv("CI_JOB_JWT_V2", "http://vat-local.abcdefg")
    asyncio.run(pipeline_auth_status.main())
    assert "Retrieve Auth Status from VAT" in caplog.text

    log.info("Test failing pipeline")
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "")
    with pytest.raises(SystemExit) as se:
        asyncio.run(pipeline_auth_status.main())
    assert se.value.code == 1
    assert "Failing Pipeline" in caplog.text
