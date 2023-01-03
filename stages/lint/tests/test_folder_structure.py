#!/usr/bin/env python3

import sys
import os
import asyncio
import pathlib
import pytest
from unittest.mock import patch
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.test.mocks.mock_classes import (
    MockProject,
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import folder_structure  # noqa E402

log = logger.setup("test_folder_structure")

@patch("dockerfile_validation.DsopProject", new=MockProject)
def test_folder_structure_main(monkeypatch, caplog):
    
    log.info("Test successful validation")
    monkeypatch.setattr(DsopProject, "validate", lambda x: x)
    asyncio.run(folder_structure.main())
    assert "Folder structure validated" in caplog.text

    log.info("Test raise AssertionError")
    monkeypatch.setattr(
        DsopProject, "validate", lambda x: raise_(AssertionError)
    )
    with pytest.raises(SystemExit) as se:
        asyncio.run(folder_structure.main())
    assert se.value.code == 1
