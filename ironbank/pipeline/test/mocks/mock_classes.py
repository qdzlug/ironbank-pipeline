#!/usr/bin/env python3

from dataclasses import dataclass, field

from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject


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
