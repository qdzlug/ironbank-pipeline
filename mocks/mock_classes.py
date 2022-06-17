from dataclasses import dataclass, field
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules"))

from hardening_manifest import HardeningManifest
from project import DsopProject


@dataclass
class MockProject(DsopProject):
    example: str = "example_str"
    hardening_manifest_path = "example_path"


@dataclass
class MockHardeningManifest(HardeningManifest):
    base_image_name: str = "example"
    base_image_tag: str = "1.0"
    resources: list[str] = field(default_factory=list)
    maintainers: list[str] = field(default_factory=list)
