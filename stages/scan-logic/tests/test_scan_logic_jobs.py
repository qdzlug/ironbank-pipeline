import json
import shutil
import sys
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from pipeline.container_tools.cosign import Cosign
from pipeline.file_parser import AccessLogFileParser, SbomFileParser
from pipeline.test.mocks.mock_classes import (
    MockImage,
    MockPath,
    MockTempDirectory,
)
from pipeline.utils.exceptions import CosignDownloadError
from common.utils import logger

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import image_verify  # noqa E402
import scan_logic_jobs  # noqa E402

log = logger.setup("test_scan_logic_jobs")

mock_sbom_pkgs = ["mock_sbom_pkg1"]
mock_access_log_pkgs = ["mock_access_log_pkg1"]


def test_write_env_vars(monkeypatch):
    log.info("Test write scan logic env vars to file")
    m_open = mock_open()
    monkeypatch.setattr(Path, "open", m_open)
    mock_args = {
        "IMAGE_TO_SCAN": "a\n",
        "COMMIT_SHA_TO_SCAN": "b\n",
        "DIGEST_TO_SCAN": "c\n",
        "BUILD_DATE_TO_SCAN": "d",
    }
    scan_logic_jobs.write_env_vars(*[m_arg.strip() for m_arg in mock_args.values()])
    # Add last remaining var that is generated
    m_open().writelines.assert_called_once_with(
        [f"{k}={v}" for k, v in mock_args.items()]
    )


def test_parse_packages(monkeypatch, caplog):
    mock_sbom_path = MockPath(path="mock_sbom.json")
    mock_access_log_path = MockPath(path="mock_access_log.json")

    monkeypatch.setattr(SbomFileParser, "parse", lambda path: mock_sbom_pkgs)
    monkeypatch.setattr(AccessLogFileParser, "parse", lambda path: mock_access_log_pkgs)

    log.info(
        "Test access log packages are added if access log is a path and does not exist"
    )
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs)

    log.info(
        "Test access log packages are added if access log is a path and does exist"
    )

    monkeypatch.setattr(MockPath, "exists", lambda self: True)
    mock_access_log_path = MockPath(path="mock_access_log.json")
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs + mock_access_log_pkgs)

    log.info(
        "Test access log packages are added if access log is a list and does not exist"
    )
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, [])
    assert pkgs == set(mock_sbom_pkgs)

    log.info(
        "Test access log packages are added if access log is a list and does exist"
    )
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_pkgs)
    assert pkgs == set(mock_sbom_pkgs + mock_access_log_pkgs)


def test_download_artifacts(monkeypatch, raise_):
    img = MockImage(tag="test", digest="test")
    mock_out = MockPath("testOut")
    mock_dock = MockPath("testDock")

    log.info("Test Cosign download fails")
    monkeypatch.setattr(
        Cosign,
        "download",
        lambda self, *args, **kwargs: raise_(CosignDownloadError),
    )
    res = scan_logic_jobs.download_artifacts(
        image=img, output_dir=mock_out, docker_config_dir=mock_dock
    )
    assert res is False

    log.info("Test Cosign download succeed")
    monkeypatch.setattr(Cosign, "download", lambda self, *args, **kwargs: None)
    res = scan_logic_jobs.download_artifacts(
        image=img, output_dir=mock_out, docker_config_dir=mock_dock
    )
    assert res is True


def test_get_old_pkgs(monkeypatch, caplog):
    img_name = "testName"
    img_dig = "testDig"
    mock_dock = MockPath("testDock")
    monkeypatch.setenv("REGISTRY_PUBLISH_URL", "example")

    log.info("Test download artifacts fails")
    monkeypatch.setattr(scan_logic_jobs, "download_artifacts", lambda **kwargs: False)
    res = scan_logic_jobs.get_old_pkgs(
        image_name=img_name, image_digest=img_dig, docker_config_dir=mock_dock
    )
    assert res == []
    assert "Download attestations failed" in caplog.text
    caplog.clear()

    log.info("Test download artifacts fails")

    log.info("Test download artifacts succeeds")
    monkeypatch.setattr(scan_logic_jobs, "download_artifacts", lambda **kwargs: True)
    monkeypatch.setattr(Path, "open", mock_open(read_data=""))
    monkeypatch.setattr(json, "load", lambda x: {"access_log": "example"})
    monkeypatch.setattr(
        scan_logic_jobs, "parse_packages", lambda old_sbom, old_al: old_al
    )
    with patch("tempfile.TemporaryDirectory", new=MockTempDirectory):
        res = scan_logic_jobs.get_old_pkgs(
            image_name=img_name, image_digest=img_dig, docker_config_dir=mock_dock
        )
        assert res == ["example"]

    log.info("Test missing access log doesn't throw error")
    monkeypatch.setattr(json, "load", lambda x: {})
    with patch("tempfile.TemporaryDirectory", new=MockTempDirectory):
        res = scan_logic_jobs.get_old_pkgs(
            image_name=img_name, image_digest=img_dig, docker_config_dir=mock_dock
        )
        assert res == []


def test_main(monkeypatch, caplog):
    # avoid actually creating env var file for all tests
    monkeypatch.setattr(scan_logic_jobs, "write_env_vars", lambda *args, **kwargs: None)
    monkeypatch.setattr(shutil, "copy", lambda *args, **kwargs: None)
    monkeypatch.setenv("IMAGE_NAME", "example/test")
    monkeypatch.setenv("IMAGE_FULLTAG", "example/test:1.0")
    monkeypatch.setenv("REGISTRY_PUBLISH_URL", "example")
    monkeypatch.setenv("ARTIFACT_STORAGE", ".")

    log.info("Test FORCE_SCAN_NEW_IMAGE saves new digest and build date")
    monkeypatch.setattr(
        scan_logic_jobs,
        "parse_packages",
        lambda x, y: set(mock_sbom_pkgs + mock_access_log_pkgs),
    )
    monkeypatch.setenv("FORCE_SCAN_NEW_IMAGE", "True")
    monkeypatch.setenv("CI_COMMIT_SHA", "example")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "abcdefg123")
    monkeypatch.setenv("BUILD_DATE", "1-2-21")
    scan_logic_jobs.main()
    assert "Skip Logic: Force scan new image" in caplog.text
    caplog.clear()

    log.info("Test CI_COMMIT_TAG not master")
    monkeypatch.setenv("FORCE_SCAN_NEW_IMAGE", "")
    monkeypatch.setenv("CI_COMMIT_TAG", "test")
    scan_logic_jobs.main()
    assert "Skip Logic: Non-master branch" in caplog.text
    caplog.clear()

    log.info("Test unable to verify image")
    monkeypatch.setenv("CI_COMMIT_TAG", "1.0.0")
    monkeypatch.setenv("DOCKER_AUTH_FILE_PULL", "example")
    monkeypatch.setattr(image_verify, "diff_needed", lambda x: None)
    with pytest.raises(SystemExit):
        scan_logic_jobs.main()
    assert "Image verify failed - Must scan new image" in caplog.text
    caplog.clear()

    log.info("Test no old packages get returned")
    monkeypatch.setattr(
        image_verify,
        "diff_needed",
        lambda x: {
            "tag": "test-tag",
            "commit_sha": "test-sha",
            "digest": "test-digest",
            "build_date": "test-date",
        },
    )
    monkeypatch.setattr(scan_logic_jobs, "get_old_pkgs", lambda **kwargs: [])
    with pytest.raises(SystemExit):
        scan_logic_jobs.main()
    assert "No old pkgs to compare - Must scan new image" in caplog.text
    caplog.clear()

    log.info("Test old image and new image package lists match")
    monkeypatch.setattr(
        scan_logic_jobs,
        "get_old_pkgs",
        lambda **kwargs: set(mock_sbom_pkgs + mock_access_log_pkgs),
    )
    scan_logic_jobs.main()
    assert "Package lists match - Able to scan old image" in caplog.text

    log.info("Test old image and new image package lists do not match")
    monkeypatch.setattr(
        scan_logic_jobs, "get_old_pkgs", lambda **kwargs: set(mock_sbom_pkgs)
    )
    scan_logic_jobs.main()
    assert "Package(s) difference detected - Must scan new image" in caplog.text
