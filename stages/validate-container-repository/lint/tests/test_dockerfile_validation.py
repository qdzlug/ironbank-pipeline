#!/usr/bin/env python3

import asyncio
import subprocess
import sys
from unittest.mock import patch
from pathlib import Path

import pytest

from pipeline.file_parser import DockerfileParser
from pipeline.test.mocks.mock_classes import MockHardeningManifest, MockProject
from pipeline.utils.exceptions import GenericSubprocessError
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import dockerfile_validation  # noqa E402

log = logger.setup("test_dockerfile_validation")

mock_path = Path(
    Path(__file__).absolute().parents[3],
    "ironbank/pipeline/test/mocks",
)


@pytest.fixture
def good_dockerfile_path():
    return Path(mock_path, "Dockerfile.test-good").as_posix()


@pytest.fixture
def bad_dockerfile_path():
    return Path(mock_path, "Dockerfile.test-bad").as_posix()


@pytest.fixture
def nonexistent_dockerfile_path():
    return Path(mock_path, "Dockerfile").as_posix()


@patch("dockerfile_validation.DsopProject", new=MockProject)
@patch("dockerfile_validation.HardeningManifest", new=MockHardeningManifest)
def test_dockerfile_validation_main(monkeypatch, caplog, raise_):
    # TODO: use pytest.parameterize to remove the duplicate code in this test

    monkeypatch.setattr(DockerfileParser, "parse", lambda x: False)

    log.info("Test successful validation on empty output")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: type("MockSubprocessResponse", (), {"stdout": ""}),
    )
    asyncio.run(dockerfile_validation.main())
    assert "No hadolint findings found" in caplog.text
    assert "Dockerfile is validated" in caplog.text
    caplog.clear()

    log.info("Test successful validation on DL and/or SC findings")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: type(
            "MockSubprocessResponse",
            (),
            {
                "stdout": "Dockerfile:1:2 DL1000 mock finding\nDockerfile:2:3 SC100 mock shell check finding"
            },
        ),
    )
    asyncio.run(dockerfile_validation.main())
    assert "SC100" in caplog.text
    assert "Dockerfile is validated" in caplog.text
    caplog.clear()

    log.info("Test hard fail on unable to parse dockerfile")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: type(
            "MockSubprocessResponse", (), {"stdout": "Mock hard failure output"}
        ),
    )
    with pytest.raises(SystemExit) as e:
        asyncio.run(dockerfile_validation.main())
    assert e.value.code == 1
    assert "Mock hard failure output" in caplog.text
    assert "Dockerfile is validated" not in caplog.text
    caplog.clear()

    log.info("Test invalid FROM statement")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: type("MockSubprocessResponse", (), {"stdout": ""}),
    )
    monkeypatch.setattr(DockerfileParser, "parse", lambda x: True)
    with pytest.raises(SystemExit) as e:
        asyncio.run(dockerfile_validation.main())
    assert e.value.code == 100
    caplog.clear()

    log.info("Test raise subprocess exception")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: raise_(subprocess.CalledProcessError(1, ["mock_cmd"])),
    )
    with pytest.raises(GenericSubprocessError):
        asyncio.run(dockerfile_validation.main())
        assert "'<lambda>', 'Running hadolint failed'" in caplog.text
    caplog.clear()
