import json
import os
import sys
import pathlib
from unittest.mock import mock_open, patch
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils.exceptions import CosignDownloadError
from ironbank.pipeline.test.mocks.mock_classes import (
    MockPath,
    MockImage,
    MockTempDirectory,
)
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import image_verify  # noqa E402
import scan_logic_jobs  # noqa E402

log = logger.setup("test_scan_logic_jobs")

mock_sbom_pkgs = ["mock_sbom_pkg1"]
mock_access_log_pkgs = ["mock_access_log_pkg1"]


def test_write_env_vars(monkeypatch):
    log.info("Test write scan logic env vars to file")
    m_open = mock_open()
    monkeypatch.setattr(pathlib.Path, "open", m_open)
    mock_args = {
        "IMAGE_TO_SCAN": "a\n",
        "DIGEST_TO_SCAN": "b\n",
        "BUILD_DATE_TO_SCAN": "c",
    }
    scan_logic_jobs.write_env_vars(*[m_arg.strip() for m_arg in mock_args.values()])
    m_open().writelines.assert_called_once_with(
        [f"{k}={v}" for k, v in mock_args.items()]
    )


def test_parse_packages(monkeypatch, caplog):
    mock_sbom_path = MockPath(path="mock_sbom.json")
    mock_access_log_path = MockPath(path="mock_access_log.json")

    log.info("Test access log packages are not added if access log path does not exist")
    monkeypatch.setattr(SbomFileParser, "parse", lambda path: mock_sbom_pkgs)
    monkeypatch.setattr(
        AccessLogFileParser, "parse", lambda self, *args: raise_(FileNotFoundError)
    )
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs)

    log.info("Test sbom and access log pkgs are combined when both exist")
    monkeypatch.setattr(AccessLogFileParser, "parse", lambda path: mock_access_log_pkgs)
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs + mock_access_log_pkgs)


def test_download_artifacts(monkeypatch):
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
    monkeypatch.setenv("BASE_REGISTRY", "example")

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
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data=""))
    monkeypatch.setattr(json, "load", lambda x: {"access_log": "example"})
    monkeypatch.setattr(
        scan_logic_jobs, "parse_packages", lambda old_sbom, old_al: old_al
    )
    with patch("tempfile.TemporaryDirectory", new=MockTempDirectory):
        res = scan_logic_jobs.get_old_pkgs(
            image_name=img_name, image_digest=img_dig, docker_config_dir=mock_dock
        )
        assert res == "example"


def test_main(monkeypatch, caplog):
    # avoid actually creating env var file for all tests
    monkeypatch.setattr(scan_logic_jobs, "write_env_vars", lambda *args, **kwargs: None)

    monkeypatch.setenv("IMAGE_NAME", "example/test")
    monkeypatch.setenv("ARTIFACT_STORAGE", ".")

    log.info("Test FORCE_SCAN_NEW_IMAGE saves new digest and build date")
    monkeypatch.setattr(
        scan_logic_jobs,
        "parse_packages",
        lambda x, y: set(mock_sbom_pkgs + mock_access_log_pkgs),
    )
    monkeypatch.setenv("FORCE_SCAN_NEW_IMAGE", "True")
    monkeypatch.setenv("IMAGE_PODMAN_SHA", "abcdefg123")
    monkeypatch.setenv("BUILD_DATE", "1-2-21")
    scan_logic_jobs.main()
    assert "Force scan new image" in caplog.text
    assert "New image digest and build date saved" in caplog.text
    caplog.clear()

    log.info("Test unable to verify image saves new digest and build date")
    monkeypatch.setenv("FORCE_SCAN_NEW_IMAGE", "")
    monkeypatch.setenv("DOCKER_AUTH_CONFIG_PULL", "example")
    monkeypatch.setattr(scan_logic_jobs, "b64decode", lambda x: x.encode())
    monkeypatch.setattr(image_verify, "diff_needed", lambda x: None)
    scan_logic_jobs.main()
    assert "Image verify failed - Must scan new image" in caplog.text
    caplog.clear()

    log.info("Test no old packages get returned")
    monkeypatch.setattr(
        image_verify, "diff_needed", lambda x: ("test-digest", "test-date")
    )
    monkeypatch.setattr(scan_logic_jobs, "get_old_pkgs", lambda **kwargs: [])
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
