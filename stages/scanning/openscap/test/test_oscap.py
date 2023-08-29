import pytest
from oscap import OpenSCAP
from pathlib import Path

from pipeline.utils.envs import Envs


class MockEnvs(Envs):
    pipeline_repo_dir: Path = Path("tmp/pipeline_repo_dir")
    scap_content_dir: Path = Path(".")
    scap_url: str = "https://download_url.com"


@pytest.fixture(scope="module")
def envs() -> Envs:
    return MockEnvs()


class MockOpenSCAP(OpenSCAP):
    def _read_file_version(self, file_version) -> str:  # type: ignore
        return "test-version"


@pytest.fixture(scope="module")
def openscap_fixture() -> OpenSCAP:
    return MockOpenSCAP()


def test_version(monkeypatch, envs, caplog):  # type: ignore
    # version is an attribute, but it is set with a function when the OpenSCAP class is initialized

    # assume that version is set
    monkeypatch.setattr(OpenSCAP, "_read_file_version", lambda x, y: "set-version")
    openscap = OpenSCAP()
    assert openscap.version == "set-version"

    # assume that version is not set
    monkeypatch.setattr(OpenSCAP, "_read_file_version", lambda x, y: "")
    with pytest.raises(ValueError):
        assert openscap._get_openscap_version()
