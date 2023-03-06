#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path

sys.path.append(Path(__file__).absolute().parents[2].as_posix())
from ironbank_py39_modules.scanner_api_handlers.anchore import Anchore  # noqa: E402


def main() -> None:
    # Get logging level, set manually when running pipeline

    anchore_scan = Anchore(
        url=os.environ["ANCHORE_SERVER_ADDRESS"],
        username=os.environ["ANCHORE_USERNAME"],
        password=os.environ["ANCHORE_PASSWORD"],
        verify=os.environ.get("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.environ.get("ANCHORE_SCANS", default="/tmp/anchore_scans")

    # Create the directory if it does not exist
    Path(artifacts_path).mkdir(parents=True, exist_ok=True)

    image = os.environ["IMAGE_TO_SCAN"]

    digest = anchore_scan.image_add(image)
    anchore_scan.image_wait(digest=digest)
    anchore_scan.get_vulns(digest=digest, image=image, artifacts_path=artifacts_path)
    anchore_scan.get_compliance(
        digest=digest, image=image, artifacts_path=artifacts_path
    )
    anchore_scan.get_version(artifacts_path=artifacts_path)


if __name__ == "__main__":
    main()
