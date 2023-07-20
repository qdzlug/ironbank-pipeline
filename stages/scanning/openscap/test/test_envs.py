# import pytest
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
    assert envs.ci_job_url == "set"
    assert envs.base_image_type == "set"
    assert envs.pipeline_repo_dir == Path("/temp/pipeline_repo")

    # should log a warning when not set
    assert envs.image_to_scan == ""
    assert "is not set" in caplog.text
    caplog.clear()

    # should default to the empty Path
    assert envs.scap_content == Path(".")
    assert "is not set" in caplog.text
    caplog.clear()

    # logger should be the name of the class
    assert envs._log.name == envs.__class__.__name__
