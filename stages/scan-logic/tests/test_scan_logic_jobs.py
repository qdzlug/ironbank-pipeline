import os
import pathlib
import sys
from unittest import mock
from unittest.mock import mock_open
import pytest
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser
from ironbank.pipeline.test.test_artifacts import mock_s3_artifact
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import MockPath

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scan_logic_jobs

log = logger.setup("test_scan_logic_jobs")


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
    mock_sbom_pkgs = ["mock_sbom_pkg1"]
    mock_access_log_pkgs = ["mock_access_log_pkg1"]

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
