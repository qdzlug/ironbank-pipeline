#!/usr/bin/env python3

import os
import sys
from pathlib import Path

sys.path.append(Path(__file__).absolute().parents[1].as_posix())

from ironbank_py39_modules.scanner_api_handlers.anchore import Anchore  # noqa: E402


def main() -> None:
    # Get logging level, set manually when running pipeline

    anchore_scan = Anchore(
        url=os.environ["ANCHORE_SERVER_ADDRESS"],
        username=os.environ["ANCHORE_USERNAME"],
        password=os.environ["ANCHORE_PASSWORD"],
        verify=os.environ.get("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.environ.get("SBOM_DIR", default="/tmp/sbom_dir")

    image = os.environ["IMAGE_FULLTAG"]

    anchore_scan.generate_sbom(image, artifacts_path, "cyclonedx-json", "json")
    anchore_scan.generate_sbom(image, artifacts_path, "spdx-tag-value", "txt")
    anchore_scan.generate_sbom(image, artifacts_path, "spdx-json", "json")
    anchore_scan.generate_sbom(image, artifacts_path, "json", "json", "syft")


if __name__ == "__main__":
    main()
