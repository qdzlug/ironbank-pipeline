#!/usr/bin/env python3

from dataclasses import dataclass, field
import subprocess

from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.utils import logger


class MockSet(set):
    def symmetric_difference(self, other):
        return False

    # overload subtraction, not needed but might be useful
    # def __sub__(self, other):
    #     return ['Example diff']


@dataclass
class MockOutput:
    mock_data: list[str] = field(default_factory=lambda: ["data1\n", "data2\n"])

    def read(self):
        return "".join(self.mock_data)

    def readline(self):
        return self.mock_data[0]

    def readlines(self):
        return self.mock_data

    def __repr__(self):
        return self.read()

    def __str__(self):
        return self.read()


@dataclass
class MockPopen(subprocess.Popen):
    stdout: str = MockOutput()
    stderr: str = MockOutput(mock_data=["err1\n", "err2\n"])
    returncode: int = 0
    mock_counter: int = 5
    poll_value: int = None

    def poll(self):
        # allow poll to run multiple times without getting stuck in while loop
        self.mock_counter -= 1
        return self.poll_value if self.mock_counter >= 0 else 0


@dataclass
class MockProcess:
    alive: bool = True
    exitcode: int = 0

    def start(self):
        return None

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.alive = False


@dataclass
class MockOpen:
    mode: str = "r"

    def __enter__(self):
        return []

    def __exit__(self, *args, **kwargs):
        pass


class MockPath:
    # TODO: remove this log message from init and provide a better way to inspect path on mock/patch
    def __init__(self, path="", *args):
        self.path: str = f"{path}{''.join((f'/{a}' for a in args))}"
        self.log = logger.setup(name="MockPath")
        self.log.info(self.path)

    def open(self, mode):
        return MockOpen(mode)

    def exists(self):
        return False

    def mkdir(self, *args, **kwargs):
        pass

    def is_symlink(self):
        return False

    def __str__(self):
        return self.path

    def __repr__(self):
        return self.path

    # overload div (/)
    def __truediv__(self, other):
        return MockPath(self, other)


@dataclass
class MockProject(DsopProject):
    example: MockPath = MockPath("example_str")
    project_path: MockPath = MockPath(".")
    hardening_manifest_path: MockPath = MockPath("example_path")
    license_path: MockPath = MockPath("license")
    readme_path: MockPath = MockPath("readme")
    dockerfile_path: MockPath = MockPath("dockerfile")
    trufflehog_conf_path: MockPath = MockPath("trufflehog")
    clamav_wl_path: MockPath = MockPath("clamav")


@dataclass
class MockHardeningManifest(HardeningManifest):
    image_name: str = "example"
    image_tag: str = "1.0"
    base_image_name: str = "base_example"
    base_image_tag: str = "2.0"
    args: dict = field(default_factory=lambda: {"a": "b", "c": "d"})
    labels: dict = field(default_factory=lambda: {"very": "cool", "wow": "awesome"})
    image_tags: list[str] = field(
        default_factory=lambda: ["1.0", "cool", "wow", "awesome"]
    )
    resources: list[str] = field(default_factory=list)
    maintainers: list[str] = field(default_factory=list)


@dataclass
class MockImage(Image):
    registry: str = "registry.example.com"
    name: str = "example1/example"
    tag: str = ""
    transport: str = ""

    # def __post_init__(*args, **kwargs):
    #     pass


@dataclass
class MockSkopeo(Skopeo):
    # TODO: update these functions to log
    def inspect(
        self, image: Image | ImageFile, raw: bool = False, log_cmd: bool = False
    ):
        return str(image) if raw else image.__dict__

    def copy(*args, **kwargs):
        return ("stdout", "stderr")
