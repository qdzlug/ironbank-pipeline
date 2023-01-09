#!/usr/bin/env python3

import os
import sys
import asyncio
import pytest
from unittest.mock import patch
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockVatAPI,
    MockResponse,
    MockGoodResponse,
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pipeline_auth_status  # noqa E402

log = logger.setup(name="test_pipeline_auth_status")


@patch("pipeline_auth_status.HardeningManifest", new=MockHardeningManifest)
@patch("pipeline_auth_status.VatAPI", new=MockVatAPI)
def test_pipeline_auth_status_main(monkeypatch, caplog):

    log.info("Test no backend server address")

    def mock_check_access_bad(self, *args, **kwargs):
        self.response = MockResponse()
    
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "")
    monkeypatch.setenv("CI_JOB_JWT_V2", "http://vat-local.abcdefg")
    monkeypatch.setattr(MockVatAPI, "check_access", mock_check_access_bad)
    with pytest.raises(SystemExit) as se:
        asyncio.run(pipeline_auth_status.main())
    assert se.value.code == 1
    assert "Failing Pipeline" in caplog.text

    log.info("Test having backend server address")

    def mock_check_access_good(self, *args, **kwargs):
        self.response = MockGoodResponse()
    
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "http://vat-local.example")
    monkeypatch.setenv("CI_JOB_JWT_V2", "http://vat-local.abcdefg")
    monkeypatch.setattr(MockVatAPI, "check_access", mock_check_access_good)

    asyncio.run(pipeline_auth_status.main())
    assert "Retrieve Auth Status from VAT" in caplog.text
