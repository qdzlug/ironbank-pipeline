#!/usr/bin/env python3

import os
import sys
import logging
import pathlib

from anchore import Anchore


def main():
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
        verify=os.getenv("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.getenv("ANCHORE_SCANS", default="/tmp/anchore_scans")

    # Create the directory if it does not exist
    pathlib.Path(artifacts_path).mkdir(parents=True, exist_ok=True)

    try:
        image = f"{os.environ['REGISTRY1_URL']}/ironbank-staging/{os.environ['IM_NAME']}:{os.environ['IMG_VERSION']}-{os.environ['CI_PIPELINE_ID']}"
    except KeyError:
        logging.exception("Could not build up full image tag")
        sys.exit(1)

    digest = anchore_scan.image_add(image)
    anchore_scan.image_wait(digest=digest)
    anchore_scan.get_vulns(digest=digest, image=image, artifacts_path=artifacts_path)
    anchore_scan.get_compliance(digest=digest, image=image, artifacts_path=artifacts_path)
    anchore_scan.get_version(artifacts_path=artifacts_path)


if __name__ == "__main__":
    sys.exit(main())
