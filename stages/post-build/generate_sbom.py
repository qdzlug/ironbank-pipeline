#!/usr/bin/env python3

import os
import sys
import logging

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ironbank/pipeline"
    )
)

from anchore import Anchore  # noqa: E402


def main() -> None:
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    anchore_scan = Anchore(
        url=os.environ["ANCHORE_SERVER_ADDRESS"],
        username=os.environ["ANCHORE_USERNAME"],
        password=os.environ["ANCHORE_PASSWORD"],
        verify=os.environ.get("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.environ.get("SBOM_DIR", default="/tmp/sbom_dir")

    image = os.environ["IMAGE_FULLTAG"]

    anchore_scan.generate_sbom(image, artifacts_path, "cyclonedx", "json")
    anchore_scan.generate_sbom(image, artifacts_path, "spdx-tag-value", "txt")
    anchore_scan.generate_sbom(image, artifacts_path, "spdx-json", "json")
    anchore_scan.generate_sbom(image, artifacts_path, "json", "json")


if __name__ == "__main__":
    main()
