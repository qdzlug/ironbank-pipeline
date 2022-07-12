#!/usr/bin/env python3

from dataclasses import dataclass, field

from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject


@dataclass
class MockOpen:
    mode: str = "r"

    def __enter__(self):
        return []

    def __exit__(self, values, something, somethingelse):
        pass


@dataclass
class MockPath:
    path: str = "changeme"

    def open(self, mode):
        return MockOpen(mode)

    def exists(self):
        return False


@dataclass
class MockProject(DsopProject):

    example: str = MockPath("example_str")
    hardening_manifest_path: str = MockPath("example_path")
    license_path: str = MockPath("license")
    readme_path: str = MockPath("readme")
    dockerfile_path: str = MockPath("dockerfile")
    trufflehog_conf_path: str = MockPath("trufflehog")
    clamav_wl_path: str = MockPath("clamav")


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
