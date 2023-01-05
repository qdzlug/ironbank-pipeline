#!/usr/bin/env python3

import os
import sys
import asyncio
import pytest
import requests
import pathlib
from unittest.mock import patch
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
)
from ironbank.pipeline.apis import VatAPI

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_auth_status  # noqa E402

log = logger.setup(name="test_pipeline_auth_status")

mock_path = pathlib.Path(
    pathlib.Path(__file__).absolute().parent.parent.parent.parent,
    "ironbank/pipeline/test/mocks",
)

@pytest.fixture
def mock_vat_api():
    return VatAPI(url="http://vat-local.example")


@patch("pipeline_auth_status.HardeningManifest", new=MockHardeningManifest)
def test_pipeline_auth_status_main(monkeypatch, mock_vat_api, mock_responses, caplog):

    log.info("Test no backend server address")
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "")
    monkeypatch.setenv("CI_JOB_JWT_V2", "http://vat-local.abcdefg")
    with pytest.raises(SystemExit) as se:
        asyncio.run(pipeline_auth_status.main())
    assert se.value.code == 1
    assert "Failing Pipeline" in caplog.text

    log.info("Test having backend server address")
    monkeypatch.setattr(requests, "get", mock_responses["200"])
    mock_vat_api.get_image("example/example/example", "1.0")
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "http://vat-local.example")
    monkeypatch.setenv("CI_JOB_JWT_V2", "http://vat-local.abcdefg")
    asyncio.run(pipeline_auth_status.main())
    assert "Retrieve Auth Status from VAT" in caplog.text
