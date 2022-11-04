#!/usr/bin/env python3

import pytest
from ironbank.pipeline.test.mocks.mock_classes import MockImage
from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup("test skopeo")


@pytest.mark.only
def test_skopeo_init():
    log.info("Test init container with params results in expected values")
    skopeo = Skopeo(authfile="authfile.json", docker_config_dir="docker_config.conf")
    assert skopeo.authfile == "authfile.json"
    assert skopeo.docker_config_dir == "docker_config.conf"

    log.info("Test init container without params results in None as default")
    skopeo = Skopeo()
    skopeo.authfile = None
    skopeo.docker_config_dir = None


def test_inspect():
    image = MockImage(registry="example.com", name="example/test", tag="1.0")
