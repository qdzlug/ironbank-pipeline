import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.append(Path(__file__).absolute().parents[1].as_posix())
from image import Image  # pylint: disable=wrong-import-position
from oscap import OpenSCAP  # pylint: disable=wrong-import-position


@dataclass
class MockImage(Image):
    """This class mocks the Image class."""

    def _pull_image(self) -> None:
        return None

    def _get_image_path(self) -> Path:
        return Path("test-path")


@dataclass
class MockOpenSCAP(OpenSCAP):
    """This class mocks the OpenSCAP class."""

    # pylint: disable=unused-argument
    def _read_file_version(self, version_file_path: Path) -> str:
        return "test-version"
