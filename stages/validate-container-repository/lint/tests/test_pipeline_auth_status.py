#!/usr/bin/env python3

import asyncio
import sys
from unittest.mock import patch
from pathlib import Path

import pytest

from pipeline.test.mocks.mock_classes import (
    MockGoodResponse,
    MockHardeningManifest,
    MockResponse,
    MockVatAPI,
)
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import pipeline_auth_status  # noqa E402

log = logger.setup(name="test_pipeline_auth_status")


@patch("pipeline_auth_status.HardeningManifest", new=MockHardeningManifest)
@patch("pipeline_auth_status.VatAPI", new=MockVatAPI)
def test_pipeline_auth_status_main(monkeypatch, caplog):
    log.info("Test no backend server address")

    def mock_check_access_bad(self, *args, **kwargs):
        self.response = MockResponse()

    monkeypatch.setenv("VAT_BACKEND_URL", "")
    monkeypatch.setenv("VAT_TOKEN", "http://vat-local.abcdefg")
    monkeypatch.setattr(MockVatAPI, "check_access", mock_check_access_bad)
    with pytest.raises(SystemExit) as e:
        asyncio.run(pipeline_auth_status.main())
    assert e.value.code == 1
    assert "Failing Pipeline" in caplog.text

    log.info("Test successful auth status")

    def mock_check_access_good(self, *args, **kwargs):
        self.response = MockGoodResponse()

    monkeypatch.setenv("VAT_BACKEND_URL", "http://vat-local.example")
    monkeypatch.setenv("VAT_TOKEN", "http://vat-local.abcdefg")
    monkeypatch.setattr(MockVatAPI, "check_access", mock_check_access_good)

    asyncio.run(pipeline_auth_status.main())
    assert "Retrieve Auth Status from VAT" in caplog.text
