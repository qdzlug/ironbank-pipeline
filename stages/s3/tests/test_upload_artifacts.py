import os
import sys
from logging import Logger
from unittest.mock import MagicMock, patch
import pytest
import requests
import subprocess
from ironbank.pipeline.utils import s3upload
from ironbank.pipeline.utils.testing import raise_
from ironbank.pipeline.test.mocks.mock_classes import (
    MockProject,
    MockResponse,
    MockHardeningManifest,
    MockPath,
)
from ironbank.pipeline.utils import logger

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import upload_artifacts  # noqa E402


log: Logger = logger.setup("test_upload_artifacts")


@patch("pathlib.Path", new=MockPath)
def test_copy_path(monkeypatch):
    mock_src: MockPath = MockPath("./..")
    mock_dest: MockPath = MockPath("./dest")

    log.info("Test path traversal caught")
    with pytest.raises(AssertionError) as ae:
        upload_artifacts.copy_path(mock_src, mock_dest)
    assert "Path traversal not safe in this function" in ae.value.args[0]

    log.info("Test copy directory")
    mock_src = MockPath("./src")
    with patch("shutil.copytree", new=MagicMock()) as mock_shutil:
        upload_artifacts.copy_path(mock_src, mock_dest)
        mock_shutil.assert_called_once_with(mock_src, mock_dest / "src")

    log.info("Test copy directory contents")
    mock_src = MockPath("./src/")
    with patch("shutil.copytree", new=MagicMock()) as mock_shutil:
        upload_artifacts.copy_path(mock_src, mock_dest)
        mock_shutil.assert_called_once_with(mock_src, mock_dest)

    log.info("Test copy file")
    mock_src = MockPath("./src/")
    monkeypatch.setattr(
        MockPath,
        "is_dir",
        lambda self: False,
    )
    with patch("shutil.copy2", new=MagicMock()) as mock_shutil:
        upload_artifacts.copy_path(mock_src, mock_dest)
        mock_shutil.assert_called_once_with(mock_src, mock_dest)


def test_post_artifact_data_vat(monkeypatch, mock_responses):
    mock_tar_path: str = "test"
    mock_published_timestamp: str = "time"
    monkeypatch.setenv("VAT_BACKEND_SERVER_ADDRESS", "test_serv_address")
    monkeypatch.setenv("CI_JOB_JWT_V2", "test_serv_address")
    monkeypatch.setenv("IMAGE_NAME", "test_img_name")
    monkeypatch.setenv("IMAGE_VERSION", "test_img_ver")
    monkeypatch.setattr(requests, "post", mock_responses["200"])

    log.info("Test successful response returned")
    resp: MockResponse = upload_artifacts.post_artifact_data_vat(
        mock_published_timestamp, mock_tar_path
    )
    assert resp.status_code == 200


@pytest.mark.only
@patch("upload_artifacts.Path", new=MockPath)
@patch("upload_artifacts.DsopProject", new=MockProject)
@patch("upload_artifacts.HardeningManifest", new=MockHardeningManifest)
def test_main(monkeypatch, mock_responses, caplog):
    monkeypatch.setenv("CI_PROJECT_DIR", "pipeline-test-project")
    monkeypatch.setenv("REPORT_TAR_NAME", "mock_REPORT_TAR_NAME")
    monkeypatch.setenv("CI_PIPELINE_ID", "mock_CI_PIPELINE_ID")
    monkeypatch.setenv("DOCUMENTATION_DIRECTORY", "mock_DOCUMENTATION_DIRECTORY")
    monkeypatch.setenv("BUILD_DIRECTORY", "mock_BUILD_DIRECTORY")
    monkeypatch.setenv("SCAN_DIRECTORY", "mock_SCAN_DIRECTORY")
    monkeypatch.setenv("SBOM_DIRECTORY", "mock_SBOM_DIRECTORY")
    monkeypatch.setenv("VAT_DIRECTORY", "mock_VAT_DIRECTORY")
    monkeypatch.setenv("S3_REPORT_BUCKET", "mock_S3_REPORT_BUCKET")
    monkeypatch.setenv("BASE_BUCKET_DIRECTORY", "mock_BASE_BUCKET_DIRECTORY")
    monkeypatch.setattr(upload_artifacts, "post_artifact_data_vat", mock_responses["200"])

    log.info("Test pipeline-test-project in CI_PROJECT_DIR")
    with pytest.raises(SystemExit) as se:
        upload_artifacts.main()
    assert se.value.code == 0

    monkeypatch.setenv("CI_PROJECT_DIR", "mock_CI_PROJECT_DIR")

    log.info("Test image_path decision tree")
    with pytest.raises(AssertionError) as ae:
        upload_artifacts.main()
    assert "No match found for image path" in ae.value.args[0]
    
    log.info("Test subprocessing and s3upload")
    def mock_project_init(self):
        self.project_path = MockPath("dsop/redhat/ubi/ubi8")

    monkeypatch.setattr(upload_artifacts.DsopProject, "__init__", mock_project_init)
    monkeypatch.setattr(upload_artifacts, "copy_path", lambda *args, **kwargs : None)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(s3upload, "upload_file", lambda *args, **kwargs: None)


    # RJ's Tech Debt:
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠊⠉⠉⠉⠓⢦⡀⠀⠀⠀⠀⢀⡤⠚⠉⠉⠉⠑⠦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⣀⠤⠔⠒⠶⠏⠀⠀⠀⠀⠀⠀⠀⠹⡀⠀⠀⢀⡎⠀⠀⠀⠀⠀⠀⠀⠙⠶⠒⠲⠤⣄⠀⠀⠀⠀
# ⠀⠀⡴⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣇⠀⠀⣸⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀
# ⠀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠔⠚⠉⠉⠀⠀⠉⠉⠓⠢⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀
# ⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⣀⣠⡤⣤⡀⠀⠀⠀⣤⡤⣄⣀⠙⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀
# ⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠀⠸⠛⠉⠁⠉⠀⠀⠀⠀⠉⠉⠉⠛⢥⠀⢳⡀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠀
# ⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⡾⠀⡴⠋⠉⠉⠳⣄⠀⠀⠀⠀⢠⠖⠉⠉⠙⢦⠀⢧⠀⠀⠀⠀⠀⠀⠀⣼⡃⠀
# ⢀⡞⠁⠀⠀⠀⠀⠀⠀⣾⠃⡜⠀⠀⠀⡆⠀⠘⡆⠀⠀⢰⠃⠀⢰⠀⠀⠀⢳⠈⡇⠀⠀⠀⠀⠀⠀⠀⢷⡀
# ⢸⠀⠀⠀⠀⢀⡴⠒⠒⣿⣰⠁⠀⣠⣴⣿⣤⠀⢹⠀⠀⡎⠀⣰⣾⣧⣄⠀⠈⡆⣿⠖⠒⢦⡀⠀⠀⠀⠈⡇
# ⠘⣆⠀⠀⠀⢸⠀⢠⠀⠉⣿⠀⠀⢿⣿⣿⣿⠀⢸⣆⣀⡇⠀⣿⣿⣿⣿⠀⠀⣿⠃⠀⡄⠀⣷⠀⠀⠀⣰⠃
# ⠀⠈⠳⣄⣀⢸⡄⠀⣧⢠⠋⠳⢄⣀⡙⡟⢡⡶⣿⣿⣿⣿⣦⡈⢻⠓⣀⣠⠴⠛⡄⢸⠁⢀⡏⣀⣠⠞⠁⠀
# ⠀⠀⠀⠀⠀⠉⠹⡄⠁⢸⡶⠒⠒⢲⡄⠁⣾⣡⣠⡿⠁⠈⣿⣷⠈⢀⣴⠛⠒⢶⠆⠀⢀⡎⠉⠁⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⡁⠒⡖⠃⢰⠀⢻⣿⣏⡀⣀⣴⣿⡟⠀⡜⠈⢲⠖⠈⡇⠀⢸⡀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⢧⠀⠈⡇⠀⢱⠀⠀⢣⠀⠙⠻⠿⠿⠟⠋⠀⡰⠁⠀⡜⠀⢰⠁⠀⡾⠃⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠣⡀⠘⡄⠀⠱⣄⠀⠉⠒⠤⠄⠠⠤⠖⠊⠀⢀⠞⠀⢠⠇⢀⡜⠁⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⢦⡈⠢⡀⠈⠑⢤⣄⣀⣀⣀⣀⣠⣤⠞⠁⢀⡴⢃⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠿⣦⡈⠐⠢⠀⠉⠙⠛⠛⠛⠉⠀⠀⠐⢁⣴⡿⢿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣶⣶⣿⣦⡀⠀⠀⠀⠀⠉⠀⠀⠀⢀⣴⣿⣵⣶⣶⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣭⣵⣾⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠈⠙⢿⣟⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠛⠛⠓⠛⠙⠋⠋⠛⠟⠛⠟⠃⠚⠻⠛⠛⠀⠀⠃⠸⠛⠛⠓⠏⠟⠛⠰⠟⠂⠀⠀⠀⠀


    log.info("Test file not found error")
    with pytest.raises(FileNotFoundError) as fnfe:
        upload_artifacts.main()
    assert "No such file or directory" in fnfe.value.args

    log.info("Test os.listdir")
    monkeypatch.setattr(os, "listdir", lambda x: None)
    upload_artifacts.main()
    caplog.clear()
    
    log.info("Test successful upload to VAT API")
    upload_artifacts.main()
    assert "Uploaded container data to VAT API" in caplog.text

    caplog.clear()

    log.info("Test VAT API Timeout")
    monkeypatch.setattr(upload_artifacts, "post_artifact_data_vat", lambda *args, **kwargs: raise_(requests.exceptions.Timeout))
    with pytest.raises(SystemExit) as se:
        upload_artifacts.main()
    assert se.value.code ==  1
    assert "Unable to reach the VAT API, TIMEOUT." in caplog.text

    caplog.clear()

    log.info("Test HTTP Error")
    monkeypatch.setattr(upload_artifacts, "post_artifact_data_vat", mock_responses["404"])
    with pytest.raises(SystemExit) as se:
        upload_artifacts.main()
    assert se.value.code ==  1
    assert "VAT HTTP error" in caplog.text
