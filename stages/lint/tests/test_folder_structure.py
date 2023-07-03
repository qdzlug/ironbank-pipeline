#!/usr/bin/env python3

import asyncio
import sys
from unittest.mock import patch
from pathlib import Path

import pytest

from pipeline.project import DsopProject
from pipeline.test.mocks.mock_classes import MockProject
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import folder_structure  # noqa E402

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
