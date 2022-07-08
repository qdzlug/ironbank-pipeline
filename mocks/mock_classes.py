from dataclasses import dataclass, field
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules"))

from hardening_manifest import HardeningManifest  # noqa: E402
from project import DsopProject  # noqa: E402


@dataclass
class MockProject(DsopProject):
    example: str = "example_str"
    hardening_manifest_path = "example_path"


@dataclass
class MockHardeningManifest(HardeningManifest):
    image_name: str = "example"
    image_tag: str = "1.0"
    base_image_name: str = "base_example"
    base_image_tag: str = "2.0"
    args: dict = field(default_factory=lambda: {"a": "b", "c": "d"})
    labels: dict = field(default_factory=lambda: {"very": "cool", "wow": "awesome"})
    resources: list[str] = field(default_factory=list)
    maintainers: list[str] = field(default_factory=list)
