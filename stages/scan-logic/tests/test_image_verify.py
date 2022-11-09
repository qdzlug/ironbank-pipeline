import os
import sys
import json
import pytest
import pathlib
from unittest.mock import mock_open, patch

from ironbank.pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockImage,
    MockProject,
    MockSkopeo,
)
from ironbank.pipeline.utils.exceptions import GenericSubprocessError
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.utils import logger

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import image_verify  # noqa E402


log = logger.setup("test_image_verify")
mock_path = pathlib.Path(pathlib.Path(__file__).absolute().parent, "mocks")
image_name = "example/test"
image_tag = "1.0"
mock_sha = "abcdefg123"


@pytest.fixture
def mock_hm():
    return MockHardeningManifest(image_name=image_name, image_tag=image_tag)


@patch("image_verify.Skopeo", new=MockSkopeo)
@patch("image_verify.Image", new=MockImage)
def test_inspect_old_image(monkeypatch, mock_hm):
    log.info("Test inspect_old_image successful")
    example_url = "http://example.com"
    monkeypatch.setenv("REGISTRY_URL_PROD", example_url)
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert (
        result
        == MockImage(
            registry=example_url, name=image_name, tag=image_tag, transport="docker://"
        ).__dict__
    )

    log.info("Test inspect_old_image throws exception")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert result is None


def test_commit_sha_equal(monkeypatch, caplog):
    log.info("Test commit_sha_equal returns False on missing label")
    img_json = {"Labels": {"example": 1}}
    revision_label_missing = image_verify.commit_sha_equal(img_json)
    assert "Image revision label does not exist" in caplog.text
    assert revision_label_missing is False
    caplog.clear()

    log.info("Test commit_sha_equal returns True on matching shas")
    img_json["Labels"] = {"org.opencontainers.image.revision": mock_sha}
    monkeypatch.setenv("CI_COMMIT_SHA", mock_sha)
    shas_match = image_verify.commit_sha_equal(img_json)
    assert shas_match is True

    log.info("Test commit_sha_equal returns False on mismatched shas")
    monkeypatch.setenv("CI_COMMIT_SHA", "different_sha")
    shas_match = image_verify.commit_sha_equal(img_json)
    assert shas_match is False
    assert "Git commit SHA difference detected" in caplog.text
    caplog.clear()


def test_parent_digest_equal(monkeypatch, caplog, mock_hm):
    log.info("Test parent_digest_equal returns false on missing label")
    img_json = {"Labels": {"example": 1}}
    digests_equal = image_verify.parent_digest_equal(img_json, mock_hm)
    assert "Parent image label does not exist" in caplog.text
    assert digests_equal is False
    caplog.clear()

    log.info(
        "Test parent_digest_equal sets new parent digest to empty on missing base_image_name in manifest"
    )
    mock_hm.base_image_name = ""
    img_json["Labels"] = {"mil.dso.ironbank.image.parent": mock_sha}
    digests_equal = image_verify.parent_digest_equal(img_json, mock_hm)
    assert digests_equal is False
    assert "New parent digest: \n" in caplog.text

    log.info("Test parent_digest_equal returns True if no parent for image")
    # technically already done above, but included for clarity
    mock_hm.base_image_name = ""
    img_json["Labels"]["mil.dso.ironbank.image.parent"] = ""
    digests_equal = image_verify.parent_digest_equal(img_json, mock_hm)

    log.info("Test parent_digest_equal returns True if parent exists and digests match")
    base_registry = "registry.example.com"
    monkeypatch.setenv("ARTIFACT_STORAGE", "ci-artifacts")
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data=""))
    monkeypatch.setattr(json, "load", lambda x: {"BASE_SHA": mock_sha})
    monkeypatch.setenv("BASE_REGISTRY", base_registry)
    mock_hm.base_image_name = "example/test"
    mock_hm.base_image_tag = "1.0"
    img_json["Labels"][
        "mil.dso.ironbank.image.parent"
    ] = f"{base_registry}/{mock_hm.base_image_name}:{mock_hm.base_image_tag}@{mock_sha}"
    digests_equal = image_verify.parent_digest_equal(img_json, mock_hm)
    assert digests_equal is True


@patch("image_verify.DsopProject", new=MockProject)
@patch("image_verify.HardeningManifest", new=MockHardeningManifest)
def test_diff_needed(monkeypatch):

    log.info("Test Digest and Label values are returned on no diff")
    mock_old_img_json = {
        "Extra Key": "something",
        "Digest": mock_sha,
        "Labels": {"org.opencontainers.image.created": "sure"},
    }
    monkeypatch.setattr(
        image_verify, "inspect_old_image", lambda x, y: mock_old_img_json
    )
    monkeypatch.setattr(image_verify, "commit_sha_equal", lambda x: True)
    monkeypatch.setattr(image_verify, "parent_digest_equal", lambda x, y: True)
    diff_needed = image_verify.diff_needed(".")
    assert diff_needed == (
        mock_old_img_json["Digest"],
        mock_old_img_json["Labels"]["org.opencontainers.image.created"],
    )

    log.info("Test None is returned on empty old img inspect")
    monkeypatch.setattr(image_verify, "inspect_old_image", lambda x, y: {})
    assert image_verify.diff_needed(".") is None

    log.info("Test None is returned on mismatched commit shas")
    monkeypatch.setattr(
        image_verify, "inspect_old_image", lambda x, y: mock_old_img_json
    )
    monkeypatch.setattr(image_verify, "commit_sha_equal", lambda x: False)
    assert image_verify.diff_needed(".") is None

    log.info("Test None is returned on mismatched parent digests")
    monkeypatch.setattr(image_verify, "commit_sha_equal", lambda x: True)
    monkeypatch.setattr(image_verify, "parent_digest_equal", lambda x, y: False)
    assert image_verify.diff_needed(".") is None
