import pytest

import sys
from pathlib import Path

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
from image import PULL_COMMAND_ERROR, GET_IMAGE_PATH_ERROR
from envs import Envs
from oscap import OpenSCAP
from pipeline.utils.exceptions import GenericSubprocessError
from mocks import MockImage


class MockOpenSCAP(OpenSCAP):
    def _read_file_version(self, version_file_path: Path) -> str:
        return "test-version"


@pytest.fixture(scope="module")
def openscap() -> OpenSCAP:
    return MockOpenSCAP()


class MockImagePullError(MockImage):
    def _pull_image(self) -> None:
        raise GenericSubprocessError


class MockImagePathError(MockImage):
    def _get_image_path(self) -> Path:
        raise GenericSubprocessError


def test_image_image_type(monkeypatch, caplog, openscap):  # type: ignore
    # should get the correct image type based on the environmant variable
    monkeypatch.setattr(Envs, "base_image_type", "ubi9-container")
    image = MockImage(openscap)
    assert image.base_type == "ubi9-container"

    # should raise an error if the base image environmental variable is invalid
    monkeypatch.setattr(Envs, "base_image_type", "invalid")
    with pytest.raises(ValueError):
        image = MockImage(openscap)
        assert "not supported" in caplog.text
        caplog.clear()


def test_security_guide(monkeypatch, openscap):  # type: ignore
    monkeypatch.setattr(Envs, "base_image_type", "ubi9-container")
    image = MockImage(openscap)
    expected: Path = Path("scap-security-guide-test-version/ssg-rhel9-ds.xml")
    assert image.security_guide_path == expected


def test_profile(monkeypatch, openscap):  # type: ignore
    monkeypatch.setattr(Envs, "base_image_type", "debian11-container")
    image = MockImage(openscap)
    expected = "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average"
    assert image.profile == expected


def test_image_path(monkeypatch, caplog, openscap):  # type: ignore
    # class should log the image path and return a path object that is not Path(".")

    monkeypatch.setattr(Envs, "base_image_type", "ubi9-container")

    image = MockImage(openscap)

    assert "Image ID:" in caplog.text
    assert isinstance(image.path, Path), "Variable 'my_path' is not a Path object."
    assert image.path != Path(""), "The value of 'my_path' is the default value"
    caplog.clear()

    # class initialization should fail if the subprocesses fail
    with pytest.raises(GenericSubprocessError):
        image = MockImagePullError(openscap)
    assert PULL_COMMAND_ERROR in caplog.text, f"Logging failed. Log: {caplog.text}"
    caplog.clear()

    with pytest.raises(GenericSubprocessError):
        image = MockImagePathError(openscap)
    assert GET_IMAGE_PATH_ERROR in caplog.text, f"Logging failed. Log: {caplog.text}"
    caplog.clear()
