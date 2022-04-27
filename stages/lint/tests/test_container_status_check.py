#!/usr/bin/env python3
import sys
import os
import logging
import pytest


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from container_status_check import create_api_findings_artifact # noqa E402
from container_status_check import create_approval_artifact # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")

@pytest.fixture
def fake_vat_response():
    response = {
        "response": "responnse",
        "example": "example"
    }
    return response

@pytest.fixture
def approval_status():
    return "Approved"

@pytest.fixture
def approval_comment():
    return "This image is approved"

def test_create_api_findings_artifacts(fake_vat_response):
    assert create_api_findings_artifact(fake_vat_response) == None

def test_create_approval_artifact(approval_status, approval_comment):
    os.environ["ARTIFACT_DIR"] = "stages/lint/tests/mock/test-artifact"
    assert create_approval_artifact(approval_status, approval_comment) == None