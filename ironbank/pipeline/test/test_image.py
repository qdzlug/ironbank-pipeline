#!/usr/bin/env python3
import pytest
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import (
    Image,
    ImageFile,
    MissingNameAndUrlError,
    MissingTagAndDigestError,
)


log = logger.setup("test_image")


def test_image_init(caplog):
    log.info("Test init image with registry, name, and digest")
    image = Image(registry="A", name="B", digest="C")
    assert image.registry_path == "A/B"
    assert str(image) == "A/B@C"

    log.info("Test init image with name, tag, and transport")
    image = Image(name="A", tag="B", transport="test:")
    assert image.registry_path == "A"
    assert str(image) == "test:A:B"

    log.info("Test init image with url")
    image = Image(url="A/B@C")
    assert image.registry_path == None
    assert str(image) == "A/B@C"

    log.info("Test init throws MissingTagAndDigestError")
    with pytest.raises(MissingTagAndDigestError) as e:
        image = Image(registry="A", name="B")
    assert e.type == MissingTagAndDigestError
    assert "Missing tag and digest" in e.value.args[0]

    log.info("Test init throws MissingNameAndUrlError")
    with pytest.raises(MissingNameAndUrlError) as e:
        image = Image(registry="A", tag="B")
    assert e.type == MissingNameAndUrlError
    assert "Missing name and url" in e.value.args[0]


def test_image_from_image():
    log.info("Test some class variables can be updated but not others")
    old_image = Image(registry="A", name="B", digest="C", transport="test:")
    new_image = old_image.from_image(registry="D", name="E", digest="F")
    assert new_image.registry_path == "D/E"
    assert str(new_image) == "test:D/E@F"


def test_imagefile_init():
    log.info("Test init ImageFile with str")
    image_file = ImageFile(file_path="testStr", transport="test:")
    assert isinstance(image_file.file_path, Path)
    assert str(image_file) == "test:testStr"

    log.info("Test init ImageFile with Path")
    image_file = ImageFile(file_path=Path("testPath"))
    assert isinstance(image_file.file_path, Path)
    assert str(image_file) == "testPath"
