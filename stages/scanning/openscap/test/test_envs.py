import sys
from pathlib import Path

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
from envs import Envs


def test_envs(monkeypatch, caplog):  # type: ignore
    # should return a value if set
    monkeypatch.setenv("CI_JOB_URL", "set")
    monkeypatch.setenv("BASE_IMAGE_TYPE", "set")
    monkeypatch.setenv("PIPELINE_REPO_DIR", "/temp/pipeline_repo")
    envs = Envs()
    assert envs.ci_job_url == "set", "Failed to set var properly"
    assert envs.base_image_type == "set", "Failed to set var properly"
    assert envs.pipeline_repo_dir == "/temp/pipeline_repo", "Failed to set var properly"

    # should log a warning when not set
    assert envs.image_to_scan == "", "Failed to set var properly"
    assert "is not set" in caplog.text, f"Logging failure: {caplog.text}"
    caplog.clear()

    # should default to the empty str
    assert envs.docker_auth_file_pull == "", "Failed to set var properly"
    assert "is not set" in caplog.text, f"Logging failure: {caplog.text}"
    assert "Source" in caplog.text, f"Logging failure: {caplog.text}"
    caplog.clear()
