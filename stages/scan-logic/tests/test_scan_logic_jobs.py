import os
import pathlib
import sys
from unittest.mock import mock_open, patch
import pytest
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser
from ironbank.pipeline.artifacts import ORASArtifact
from ironbank.pipeline.utils.exceptions import ORASDownloadError
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.test.mocks.mock_classes import MockPath, MockSet

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

    log.info("Test sys.exit is called on missing sbom path")
    with pytest.raises(SystemExit):
        scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert "SBOM not found - Exiting" in caplog.text

    log.info("Test access log packages are not added if access log path does not exist")
    mock_sbom_path.exists = lambda: True
    monkeypatch.setattr(SbomFileParser, "parse", lambda path: mock_sbom_pkgs)
    monkeypatch.setattr(AccessLogFileParser, "parse", lambda path: mock_access_log_pkgs)
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs)

    log.info("Test sbom and access log pkgs are combined when both exist")
    mock_access_log_path.exists = lambda: True
    pkgs = scan_logic_jobs.parse_packages(mock_sbom_path, mock_access_log_path)
    assert pkgs == set(mock_sbom_pkgs + mock_access_log_pkgs)


@patch("scan_logic_jobs.Path", new=MockPath)
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

    log.info("Testing diff needed and ORAS download failed")
    monkeypatch.setenv("BASE_REGISTRY", "example-registry")
    monkeypatch.setattr(
        image_verify, "diff_needed", lambda x: ("test-digest", "test-date")
    )
    monkeypatch.setattr(
        ORASArtifact,
        "download",
        lambda self, *args: raise_(ORASDownloadError("Test ORAS download failed")),
    )
    scan_logic_jobs.main()
    assert "SBOM diff required to determine image to scan" in caplog.text
    assert (
        "Downloading artifacts for image: example-registry/example/test@test-digest"
        in caplog.text
    )
    assert "ORAS download failed - Must scan new image" in caplog.text
    caplog.clear()

    log.info("Test old image and new image package lists match")
    monkeypatch.setattr(
        scan_logic_jobs,
        "parse_packages",
        lambda x, y: MockSet(),
    )
    monkeypatch.setattr(ORASArtifact, "download", lambda self, *args: True)
    scan_logic_jobs.main()
    assert "Package lists match - Able to scan old image" in caplog.text

    log.info("Test old image and new image package lists do not match")
    monkeypatch.setattr(MockSet, "symmetric_difference", lambda self, x: True)
    scan_logic_jobs.main()
    assert "Package lists match - Able to scan old image" in caplog.text