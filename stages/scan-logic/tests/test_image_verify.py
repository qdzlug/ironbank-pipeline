import pathlib
import os
import re
from unittest.mock import patch
import pytest
import sys

from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockImage,
    MockSkopeo,
)
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.utils.testing import raise_

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import image_verify  # noqa E402

mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")
image_name = "example/test"
image_tag = "1.0"


@pytest.fixture
def mock_hm():
    return MockHardeningManifest(image_name=image_name, image_tag=image_tag)


@patch("image_verify.Skopeo", new=MockSkopeo)
@patch("image_verify.Image", new=MockImage)
def test_inspect_old_image(monkeypatch, mock_hm):
    example_url = "http://example.com"
    monkeypatch.setenv("REGISTRY_URL_PROD", example_url)
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert (
        result
        == MockImage(
            registry=example_url, name=image_name, tag=image_tag, transport="docker://"
        ).__dict__
    )

    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert result == None


@pytest.mark.only
def test_commit_sha_equal(caplog):
    revision_label_missing = image_verify.commit_sha_equal({"Labels": {"example": 1}})
    assert "Image revision label does not exist" in caplog.text
    assert revision_label_missing == False
    caplog.clear()
