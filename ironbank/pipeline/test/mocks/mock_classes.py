#!/usr/bin/env python3

from dataclasses import dataclass, field
from pathlib import PosixPath
import subprocess
import tempfile
import requests
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.apis import VatAPI
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package


class MockSet(set):
    def symmetric_difference(self, other):
        return False

    # overload subtraction, not needed but might be useful
    # def __sub__(self, other):
    #     return ['Example diff']


@dataclass
class MockOutput:
    mock_data: list[str] = field(
        default_factory=lambda: [
            "data1\n",
            "data2\n",
        ]
    )
    line_num: int = 0

    def read(self):
        return "".join(self.mock_data)

    def readline(self):
        # return MockReadline(self.mock_data)
        self.line_num += 1
        return (
            self.mock_data[self.line_num - 1]
            if self.line_num <= len(self.mock_data)
            else ""
        )

    def readlines(self):
        return self.mock_data

    def __repr__(self):
        return self.read()

    def __str__(self):
        return self.read()


@dataclass
class MockJson:
    def dump(*args, **kwargs):
        pass


@dataclass
class MockResponse:
    returncode: int = 1
    status_code: int = 500
    text: str = "example"
    content: str = "example"
    stderr: str = "canned_error"
    stdout: str = "It broke"

    def __enter__(self):
        return self

    def __exit__(self, mock1, mock2, mock3):
        pass

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.exceptions.HTTPError

    def iter_content(self, chunk_size=2048):
        return [b"abcdef", b"ghijkl", b"mnopqrs"]

    def json(self):
        return {"status_code": self.status_code, "text": self.text}


@dataclass
class MockPopen(subprocess.Popen):
    stdout: MockOutput = field(default_factory=lambda: MockOutput())
    stderr: MockOutput = field(
        default_factory=lambda: MockOutput(mock_data=["err1\n", "err2\n"])
    )
    encoding: str = "UTF-10000"
    returncode: int = 0
    poll_counter: int = 5
    poll_value: int = None

    def poll(self):
        # allow poll to run multiple times without getting stuck in while loop
        self.poll_counter -= 1
        return None if self.poll_counter >= 0 else self.returncode


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
    encoding: str = "utf-8"

    def __enter__(self):
        return MockOutput()

    def __exit__(self, *args, **kwargs):
        pass


class MockPath(PosixPath):
    # TODO: remove this log message from init and provide a better way to inspect path on mock/patch

    def __new__(cls, path, *args):
        self = object.__new__(cls)
        self.path = f"{path}{''.join((f'/{a}' for a in args))}"
        self.log = logger.setup(name="MockPath")
        return self

    def open(self, mode, encoding="utf-8"):
        return MockOpen(mode, encoding)

    def exists(self):
        return False

    def mkdir(self, *args, **kwargs):
        pass

    def as_posix(self):
        return self.path

    def is_dir(self):
        return True

    def is_symlink(self):
        return False

    def write_text(self, data, encoding=None, errors=None, newline=None):
        return ""

    def __eq__(self, path) -> bool:
        return self.as_posix() == path.as_posix()

    def __contains__(self, sub_str):
        return sub_str in self.as_posix()

    def __str__(self):
        return self.path

    def __repr__(self):
        return self.path

    # overload div (/)
    def __truediv__(self, other):
        return MockPath(self, other)


@dataclass
class MockTempDirectory(tempfile.TemporaryDirectory):
    prefix: str

    def __enter__(self):
        return f"{self.prefix}/"

    def __exit__(self, *args):
        pass


@dataclass
class MockProject(DsopProject):
    example: MockPath = field(default_factory=lambda: MockPath("example_str"))
    project_path: MockPath = field(default_factory=lambda: MockPath("."))
    hardening_manifest_path: MockPath = field(
        default_factory=lambda: MockPath("example_path")
    )
    license_path: MockPath = field(default_factory=lambda: MockPath("license"))
    readme_path: MockPath = field(default_factory=lambda: MockPath("readme"))
    dockerfile_path: MockPath = field(default_factory=lambda: MockPath("dockerfile"))
    trufflehog_conf_path: MockPath = field(
        default_factory=lambda: MockPath("trufflehog")
    )
    clamav_wl_path: MockPath = field(default_factory=lambda: MockPath("clamav"))


@dataclass
class MockHardeningManifest(HardeningManifest):
    image_name: str = "example"
    image_tag: str = "1.0"
    base_image_name: str = "base_example"
    base_image_tag: str = "2.0"
    validate: bool = False
    invalid_labels = None
    invalid_maintainers = None
    invalid_image_sources = None
    args: dict = field(default_factory=lambda: {"a": "b", "c": "d"})
    labels: dict = field(default_factory=lambda: {"very": "cool", "wow": "awesome"})
    image_tags: list[str] = field(
        default_factory=lambda: ["1.0", "cool", "wow", "awesome"]
    )
    resources: list[str] = field(default_factory=list)
    maintainers: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class MockPackage(Package):
    kind: str = "mock_kind"
    name: str = "mock_name"
    version: str = "mock_version"
    url: str = "mock_url"


@dataclass
class MockImage(Image):
    registry: str = "registry.example.com"
    name: str = "example1/example"
    tag: str = ""
    transport: str = ""

    # def __post_init__(*args, **kwargs):
    #     pass


@dataclass
class MockVatAPI(VatAPI):
    response: requests.Response = None

    def check_access(self, image_name, create_request=False) -> None:
        self.response = MockResponse()


class MockGoodResponse:
    status_code: int = 200
    text: str = "example"

    def json(self):
        return {"status_code": self.status_code, "text": self.text}


@dataclass
class MockCosign(Cosign):
    def verify(
        cls,
        image: Image,
        pubkey: MockPath = None,
        certificate: MockPath = None,
        certificate_chain: MockPath = None,
        signature_digest_algorithm="sha256",
        log_cmd: bool = False,
    ):
        return str(image)


@dataclass
class MockSkopeo(Skopeo):
    # TODO: update these functions to log
    def inspect(
        self, image: Image | ImageFile, raw: bool = False, log_cmd: bool = False
    ):
        return str(image) if raw else image.__dict__

    def copy(*args, **kwargs):
        return ("stdout", "stderr")
