#!/usr/bin/env python3

import json
import subprocess

import pytest

from ironbank.pipeline.container_tools.skopeo import CopyException, Skopeo
from ironbank.pipeline.test.mocks.mock_classes import MockImage
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import GenericSubprocessError

log = logger.setup("test_skopeo")

mock_image = MockImage(
    registry="example.com", name="example/test", tag="1.0", transport="docker://"
)


def test_skopeo_init():
    log.info("Test init container with params results in expected values")
    skopeo = Skopeo(authfile="authfile.json", docker_config_dir="docker_config.conf")
    assert skopeo.authfile == "authfile.json"
    assert skopeo.docker_config_dir == "docker_config.conf"

    log.info("Test init container without params results in None as default")
    skopeo = Skopeo()
    assert skopeo.authfile is None
    assert skopeo.docker_config_dir is None


def test_inspect(monkeypatch, caplog, raise_):
    mock_image = MockImage(registry="example.com", name="example/test", tag="1.0")
    skopeo = Skopeo()

    log.info("Test default value for raw returns dictionary of json output")
    mock_dict_result = {"image": str(mock_image)}
    mock_raw_result = str(mock_dict_result)
    # define and instantiate object with one property
    mock_subprocess_response = type(
        "MockSubprocessResponse", (), {"stdout": mock_raw_result}
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: mock_subprocess_response
    )
    monkeypatch.setattr(json, "loads", lambda x: mock_dict_result)
    result = skopeo.inspect(mock_image)
    assert result == mock_dict_result

    log.info("Test raw=True returns different value ")
    result = skopeo.inspect(mock_image, raw=True)
    assert result == mock_raw_result

    log.info(
        "Test SubprocessError is caught by decorator and GenericSubprocessError is thrown"
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: raise_(subprocess.SubprocessError)
    )
    with pytest.raises(GenericSubprocessError):
        result = skopeo.inspect(mock_image)
    assert "Skopeo.inspect failed" in caplog.text
    caplog.clear()


def test_copy(monkeypatch, caplog, raise_):
    skopeo = Skopeo()
    mock_src = mock_image.from_image()
    mock_dest = MockImage(
        registry="localhost",
        name="test/example",
        tag="0.1",
        transport="container-storage:",
    )

    log.info("Test missing src or dest raises exception")
    with pytest.raises(CopyException) as e:
        skopeo.copy(None, mock_dest)
    assert "Missing source from copy command" in e.value.args
    with pytest.raises(CopyException) as e:
        skopeo.copy(mock_src, None)
    assert "Missing destination from copy command" in e.value.args

    log.info("Test missing transport raises exception")
    with pytest.raises(CopyException) as e:
        skopeo.copy(mock_src.from_image(transport=None), mock_dest)
    assert "Missing transport for source" in e.value.args
    with pytest.raises(CopyException) as e:
        skopeo.copy(mock_src, mock_dest.from_image(transport=None))
    assert "Missing transport for destination" in e.value.args

    mock_subprocess_response = type(
        "MockSubprocessResponse", (), {"stdout": "Successful Copy", "stderr": ""}
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: mock_subprocess_response
    )
    log.info("Test successful copy with additional tags")
    result = skopeo.copy(mock_src, mock_dest, additional_tags=["--test", "abc"])
    assert result == ("Successful Copy", "")

    log.info(
        "Test SubprocessError is caught by decorator and GenericSubprocessError is thrown"
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: raise_(subprocess.SubprocessError)
    )
    with pytest.raises(GenericSubprocessError):
        result = skopeo.copy(mock_src, mock_dest)
    assert "Skopeo.copy failed" in caplog.text
    caplog.clear()
