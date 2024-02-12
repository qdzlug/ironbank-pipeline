#!/usr/bin/env python3

import os
import sys
from pathlib import Path
from multiprocessing import Pool
from functools import partial

# pylint: disable=C0413
sys.path.append(Path(__file__).absolute().parents[2].as_posix())
from ironbank_py39_modules.scanner_api_handlers.anchore import (
    Anchore,
)

def generate_sbom_parallel(anchore_scan, image, artifacts_path, fmt):
    anchore_scan.generate_sbom(image, artifacts_path, fmt[0], fmt[1])

def main() -> None:
    """Main function that initializes an Anchore scanner and generates Software
    Bill of Materials (SBOM) in multiple formats for a specified image.

    The function retrieves configuration parameters from environment variables including the Anchore scanner
    details and the full tag of the image for scanning. It also gets the path for storing SBOM files which
    defaults to "/tmp/sbom_dir" if not provided.

    The SBOMs are generated in the following formats:
    - cyclonedx-json
    - spdx-tag-value
    - spdx-json
    - json (using Syft tool)

    All SBOM files are saved in the specified path or the default path if not provided.

    :raises KeyError: If required environment variables are not set.
    """
    # Get logging level, set manually when running pipeline

    anchore_scan = Anchore(
        url=os.environ["ANCHORE_URL"],
        username=os.environ["ANCHORE_USERNAME"],
        password="",  # No password required for syft
        verify=os.environ.get("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.environ.get("SBOM_DIR", default="/tmp/sbom_dir")

    image = os.environ["IMAGE_FULLTAG"]

    sbom_formats = [("cyclonedx-json", "json"), ("spdx-tag-value", "txt"), ("spdx-json", "json")]

    print("beginning pool")
    with Pool() as pool:
        pool.map(generate_sbom_parallel, sbom_formats)

    anchore_scan.generate_sbom(image, artifacts_path, "json", "json", "syft")

if __name__ == "__main__":
    main()
