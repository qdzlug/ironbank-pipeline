from dataclasses import dataclass


@dataclass
class MockProject:
    example: str = "example_str"
    hardening_manifest_path = "example_path"


@dataclass
class MockHardeningManifest:
    base_image_name: str = "example"
    base_image_tag: str = "1.0"
