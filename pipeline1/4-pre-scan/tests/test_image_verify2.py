import json
import sys
from unittest.mock import mock_open, patch
from pathlib import Path

import pytest

from pipeline.test.mocks.mock_classes import (
    MockHardeningManifest,
    MockImage,
    MockProject,
    MockSkopeo,
)
from pipeline.utils.exceptions import GenericSubprocessError
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import image_verify  # noqa E402

log = logger.setup("test_image_verify")
mock_path = Path(Path(__file__).absolute().parent, "mocks")
IMAGE_NAME = "example/test"
IMAGE_TAG = "1.0"
MOCK_SHA = "abcdefg123"


@pytest.fixture
def mock_hm():
    return MockHardeningManifest(image_name=IMAGE_NAME, image_tag=IMAGE_TAG)


@patch("image_verify.Skopeo", new=MockSkopeo)
@patch("image_verify.Image", new=MockImage)
def test_inspect_old_image(monkeypatch, mock_hm, raise_):
    log.info("Test inspect_old_image successful")
    example_url = "http://example.com"
    monkeypatch.setenv("REGISTRY_PUBLISH_URL", example_url)
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert (
        result
        == MockImage(
            registry=example_url, name=IMAGE_NAME, tag=IMAGE_TAG, transport="docker://"
        ).__dict__
    )

    log.info("Test inspect_old_image throws exception")
    monkeypatch.setattr(
        MockSkopeo, "inspect", lambda *args, **kwargs: raise_(GenericSubprocessError)
    )
    result = image_verify.inspect_old_image(mock_hm, ".")
    assert result is None


def test_verify_image_properties(monkeypatch, caplog, mock_hm):
    log.info("Test new parent digest set to empty on missing base_image_name")
    mock_hm.base_image_name = ""
    monkeypatch.setenv("CI_COMMIT_SHA", MOCK_SHA)
    img_json = {
        "Labels": {
            "mil.dso.ironbank.image.parent": MOCK_SHA,
            "org.opencontainers.image.revision": MOCK_SHA,
        }
    }
    verify_result = image_verify.verify_image_properties(img_json, mock_hm)
    assert verify_result is False
    assert "New parent digest: \n" in caplog.text

    log.info("Test return False on mismatched shas")
    monkeypatch.setenv("CI_COMMIT_SHA", "different_sha")
    shas_match = image_verify.verify_image_properties(img_json, mock_hm)
    assert shas_match is False
    assert "Git commit SHA difference detected" in caplog.text
    caplog.clear()

    log.info("Test return True if no parent for image")
    monkeypatch.setenv("CI_COMMIT_SHA", MOCK_SHA)
    # technically already done above, but included for clarity
    img_json["Labels"]["mil.dso.ironbank.image.parent"] = ""
    verify_result = image_verify.verify_image_properties(img_json, mock_hm)
    assert verify_result is True

    log.info("Test return True if parent exists and commit shas/digests match")
    base_registry = "registry.example.com"
    monkeypatch.setenv("ARTIFACT_STORAGE", "ci-artifacts")
    monkeypatch.setattr(Path, "open", mock_open(read_data=""))
    monkeypatch.setattr(json, "load", lambda x: {"BASE_SHA": MOCK_SHA})
    monkeypatch.setenv("BASE_REGISTRY", base_registry)
    mock_hm.base_image_name = "example/test"
    mock_hm.base_image_tag = "1.0"
    img_json["Labels"][
        "mil.dso.ironbank.image.parent"
    ] = f"{base_registry}/{mock_hm.base_image_name}:{mock_hm.base_image_tag}@{MOCK_SHA}"
    verify_result = image_verify.verify_image_properties(img_json, mock_hm)
    assert verify_result is True


@patch("image_verify.DsopProject", new=MockProject)
@patch("image_verify.HardeningManifest", new=MockHardeningManifest)
@patch("image_verify.Image", new=MockImage)
def test_diff_needed(monkeypatch, caplog, raise_):
    log.info("Test Digest and Label values are returned on no diff")
    example_url = "http://example.com"
    monkeypatch.setenv("REGISTRY_PUBLISH_URL", example_url)
    monkeypatch.setenv("CI_SERVER_URL", "repo1.dso.mil")
    monkeypatch.setenv("KMS_KEY_SHORT_ARN", "kmsKey")
    monkeypatch.setenv("COSIGN_CERT", "cert")
    monkeypatch.setenv("COSIGN_PUBLIC_KEY", "publicKey")
    monkeypatch.setenv("COSIGN_CERTIFICATE_CHAIN", "chain")
    mock_old_img_json = {
        "Extra Key": "something",
        "Tag": IMAGE_TAG,
        "Commit": MOCK_SHA,
        "Digest": MOCK_SHA,
        "Labels": {
            "org.opencontainers.image.created": "sure",
            "org.opencontainers.image.revision": "abcdefg123",
        },
    }
    monkeypatch.setattr(
        image_verify, "inspect_old_image", lambda x, y: mock_old_img_json
    )
    monkeypatch.setattr(image_verify, "verify_image_properties", lambda x, y: True)
    monkeypatch.setattr(image_verify.Cosign, "verify", lambda *args, **kwargs: True)
    diff_needed = image_verify.diff_needed(".")
    assert diff_needed == {
        "tag": mock_old_img_json["Tag"],
        "commit_sha": mock_old_img_json["Commit"],
        "digest": mock_old_img_json["Digest"],
        "build_date": mock_old_img_json["Labels"]["org.opencontainers.image.created"],
    }

    log.info("Test None is returned on empty old img inspect")
    monkeypatch.setenv("CI_SERVER_URL", "")
    monkeypatch.setattr(image_verify, "inspect_old_image", lambda x, y: {})
    assert image_verify.diff_needed(".") is None

    log.info("Test None is returned on mismatched commit shas or parent digests")
    monkeypatch.setattr(
        image_verify, "inspect_old_image", lambda x, y: mock_old_img_json
    )
    monkeypatch.setattr(image_verify, "verify_image_properties", lambda x, y: False)
    assert image_verify.diff_needed(".") is None

    log.info("Test sys exit on key error")
    monkeypatch.setattr(
        image_verify, "verify_image_properties", lambda x, y: raise_(KeyError)
    )
    with pytest.raises(SystemExit):
        image_verify.diff_needed(".")
    assert "Digest or label missing for old image" in caplog.text
    caplog.clear()
