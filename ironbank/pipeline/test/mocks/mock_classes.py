#!/usr/bin/env python3

import inspect
import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import PosixPath
from typing import Any, Callable
from xml.etree.ElementTree import Element, ElementTree

import requests
from requests import Session

from ironbank.pipeline.apis import VatAPI
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.harbor import (
    HarborRobot,
    HarborRobotPermissions,
)
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.scan_report_parsers.oscap import (
    OscapComplianceFinding,
    OscapFinding,
    OscapOVALFinding,
    RuleInfo,
    RuleInfoOVAL,
)
from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser
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
    write_data: Any = None

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

    def write(self, write_data: Any):
        self.write_data = write_data

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
    status_code: int = 500
    text: str = "example"
    content: str = "example"
    headers: dict = field(default_factory=dict)

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


# Mock for subprocess.CompletedProcess, the return value for subprocess.run
@dataclass
class MockCompletedProcess:
    returncode: int = 1
    text: str = "example"
    stderr: str = "canned_error"
    stdout: str = "It broke"


@dataclass
class MockSession(Session):
    def get(*args, **kwargs):
        return MockResponse()

    def post(*args, **kwargs):
        return MockResponse()

    def put(*args, **kwargs):
        return MockResponse()

    def delete(*args, **kwargs):
        return MockResponse()


# pylint: disable=W0108
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def poll(self):
        # allow poll to run multiple times without getting stuck in while loop
        self.poll_counter -= 1
        return None if self.poll_counter >= 0 else self.returncode


# pylint: enable=W0108


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

    def __new__(cls, path, *args, mock_data=None):
        self = object.__new__(cls)
        self.path = f"{path}{''.join((f'/{a}' for a in args))}"
        self.log = logger.setup(name="MockPath")
        self.mock_data = mock_data
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

    def write_text(self, mock_data, encoding=None, errors=None, newline=None):
        return ""

    def read_text(self, encoding=None, *args, **kwargs):
        return self.mock_data

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
    invalid_partner_advocates = None
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
class MockPaginatedRequest:
    session: requests.Session
    url: str
    query: str = ""
    page: int = 1
    page_size: int = 100

    def __post_init__(self):
        pass

    def get(self):
        return [{"name": "ironbank"}, {"name": "ironbank"}, {"name": "ironbank"}]


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
class MockSkopeo(Skopeo):
    # TODO: update these functions to log
    def inspect(
        self, image: Image | ImageFile, raw: bool = False, log_cmd: bool = False
    ):
        return str(image) if raw else image.__dict__

    def copy(*args, **kwargs):
        return ("stdout", "stderr")


@dataclass
class MockOscapComplianceFinding(OscapComplianceFinding):
    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return cls


@dataclass
class MockOscapOVALFinding(OscapOVALFinding):
    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return cls


@dataclass
class MockOscapFinding(OscapFinding):
    identifier: str = "mock_identifier"
    severity: str = "mock_severity"
    identifiers: tuple = field(default_factory=lambda: ())

    @classmethod
    def get_findings_from_rule_info(cls, rule_info):
        return [
            MockOscapComplianceFinding(
                identifier=rule_info.identifier, rule_id="rule1", severity=""
            ),
        ]


@dataclass
class MockElementTree:
    def find(self, *args, **kwargs) -> None:
        return (
            MockElement(xml_path=args[0], text=f"{args[0]}_mock_element_text")
            if args
            else MockElement(
                xml_path=kwargs["path"], text=f"{kwargs['path']}_mock_element_text"
            )
            if kwargs
            else MockElement()
        )

    def findall(self, *args, **kwargs) -> None:
        return [self.find(*args, **kwargs)]


@dataclass
class MockElement(MockElementTree):
    text: str = "mock_element_text"
    attrib: dict = field(
        default_factory=lambda: {
            "idref": "example_id",
            "href": "mock_href",
            "name": "mock_name",
            "severity": "medium",
            "time": "2:30",
        }
    )
    # xml_path is provided to spy on the xml path used in find/findall
    xml_path: str = ""
    # fake_type is provided to easily switch between MockRuleInfo and MockRuleInfoOVAL type in the MockRuleInfo constructor
    fake_type: str = "compliance"


@dataclass
class MockRuleInfo(RuleInfo):
    rule_id: str = "12345"
    title: str = "Mock Rule Title"
    severity: str = "medium"

    def __new__(
        cls, root: MockElementTree, rule_result: MockElement, *args, **kwargs
    ) -> Callable:  # pylint: disable=unused-argument
        return object.__new__(
            MockRuleInfoOVAL if (rule_result.fake_type == "OVAL") else MockRuleInfo
        )

    def __post_init__(self, root: ElementTree, rule_result: Element):
        self.identifier = str(random.randint(0, 1000))

    @classmethod
    def get_result(cls, rule_result: MockElement) -> str:
        return "mock_result"

    @classmethod
    def _format_reference(cls, ref: Element) -> str:
        return "mock_formatted_reference"

    @classmethod
    def get_results(cls, root: MockElement, results_filter: list[str]):
        return [
            MockElement(text="abc"),
            MockElement(text="def"),
            MockElement(text="ghi"),
        ]

    def set_identifiers(self, rule_obj: MockElement) -> None:
        self.identifiers = "mock_identifiers"

    def set_result(self, rule_obj: MockElement) -> None:
        self.result = "mock_result"

    def set_references(self, rule_obj: MockElement) -> None:
        self.references = "mock_references"

    def set_rationale(self, rule_obj: MockElement) -> None:
        self.rationale = "mock_rationale"

    def set_description(self, *args, **kwargs) -> None:
        self.description = "mock_description"


@dataclass
class MockRuleInfoOVAL(MockRuleInfo, RuleInfoOVAL):
    findings: list[MockElement] = field(default_factory=lambda: [MockElement()])

    def __post_init__(self, root: ElementTree, rule_result: Element):
        pass

    def set_oval_val_from_ref(self, val: str, rule_result: Element) -> None:
        self._log.warning("%s set for %s", rule_result.attrib[val], val)

    def set_oval_name(self, rule_obj: MockElement):
        self.oval_name = "mock_oval_name"

    def set_oval_href(self, rule_obj: MockElement):
        self.oval_href = "mock_oval_href"

    def set_values_from_oval_report(self, rule_obj: MockElement):
        pass

    def set_findings(self):
        self.findings = ["mock_oval_findings"]

    def set_definition(self, oval_root: ElementTree) -> None:
        self.definition = MockElement("mock_definition")

    def set_description(self, *args, **kwargs) -> None:
        self.description = "mock_oval_description"

    @classmethod
    def get_oval_url(cls, finding_href: str) -> str:
        return "https://mock_url.mock"

    @classmethod
    def download_oval_definitions(cls, url: str) -> list[dict]:
        return MockPath("example", "path")


@dataclass
class MockReportParser(ReportParser):
    @classmethod
    def dedupe_findings_by_attr(
        cls, findings: list[MockOscapFinding], attribute: str
    ) -> list[MockOscapFinding]:
        return findings


@dataclass
class TestUtils:
    @staticmethod
    def get_attrs_from_object(obj: object):
        obj_attrs = inspect.getmembers(obj, lambda x: not inspect.isroutine(x))
        # return attributes with magic methods and abc private attributes removed
        return [
            attr[0]
            for attr in obj_attrs
            if (not attr[0].endswith("__") and attr[0] != "_abc_impl")
        ]


@dataclass
class MockHarborRobot(HarborRobot):
    name: str = "pretend"
    email: str = "fake@fake.lie"
    description: str = "You may think you can read, but you can't"
    expires_at: str = "yesterday"
    duration: int = 1
    disable: bool = False
    level: str = "highest"
    permissions: list["HarborRobotPermissions"] = field(default_factory=lambda: [])


# this isn't currently used, but will be needed for refactor changes in !1181
# will need to inherit from HarborRobotsApi once available
@dataclass
class MockHarborRobotsApi:
    robots: list[MockHarborRobot] = field(default_factory=lambda: [])

    def get_robot_accounts(self):
        self.robots.append(
            MockHarborRobot(
                name="mock_robot_1",
                description="This is a mock robot.",
                expires_at="never",
            )
        )
        self.robots.append(
            MockHarborRobot(
                name="mock_robot_2",
                description="This is another mock robot.",
                expires_at="never",
            )
        )

    def create_robot(self, robot: MockHarborRobot):
        return {"message": "Mock robot successfully created"}


@dataclass
class MockHarborRobotPermissions(HarborRobotPermissions):
    access: list[dict] = field(
        default_factory=lambda: [
            {"resource": "bar", "action": "truffle"},
            {"resource": "foo", "action": "carrot"},
        ]
    )
    kind: str = "baz"
    namespace: str = "/sprite"
