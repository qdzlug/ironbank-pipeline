#!/usr/bin/env python3

import asyncio
import os
import sys
from unittest.mock import patch

import pytest

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.test.mocks.mock_classes import MockProject
from ironbank.pipeline.utils import logger

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import folder_structure

log = logger.setup("test_folder_structure")


@patch("dockerfile_validation.DsopProject", new=MockProject)
def test_folder_structure_main(monkeypatch, caplog, raise_):
    log.info("Test successful validation")
    monkeypatch.setattr(DsopProject, "validate", lambda x: x)
    asyncio.run(folder_structure.main())
    assert "Folder structure validated" in caplog.text

    log.info("Test raise AssertionError")
    monkeypatch.setattr(DsopProject, "validate", lambda x: raise_(AssertionError))
    with pytest.raises(SystemExit) as e:
        asyncio.run(folder_structure.main())
    assert e.value.code == 1
