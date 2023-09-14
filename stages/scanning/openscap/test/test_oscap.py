import pytest
import re
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

    @classmethod
    def oscap_version_cli_command(cls) -> str:  # type: ignore
        return """OpenSCAP command line tool (oscap) 1.3.7
Copyright 2009--2021 Red Hat Inc., Durham, North Carolina.

==== Supported specifications ====
SCAP Version: 1.3
XCCDF Version: 1.2
OVAL Version: 5.11.1
CPE Version: 2.3
CVSS Version: 2.0
CVE Version: 2.0
Asset Identification Version: 1.1
Asset Reporting Format Version: 1.1
CVRF Version: 1.1
"""


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


def test_get_scap_version(openscap_fixture):
    version = openscap_fixture.get_scap_version()
    assert re.match(r"^\d+\.\d+$", version)


def test_get_cli_version(openscap_fixture):
    version = openscap_fixture.get_cli_version()
    assert re.match(r"^\d+\.\d+\.\d+$", version)
