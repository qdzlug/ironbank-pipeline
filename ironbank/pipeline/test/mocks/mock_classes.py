#!/usr/bin/env python3

from dataclasses import dataclass, field

from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.container_tools.skopeo import Skopeo


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

    def is_symlink(self):
        return False


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
    tag: str = "1.0"
    transport: str = "nah://"

    def __post_init__(*args, **kwargs):
        pass


@dataclass
class MockSkopeo(Skopeo):
    # TODO: update these functions to log
    def inspect(self, image: Image | ImageFile, raw: bool = False):
        return str(image) if raw else image.__dict__

    def copy(*args, **kwargs):
        return ("stdout", "stderr")
