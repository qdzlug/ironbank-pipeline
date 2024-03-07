#!/usr/bin/env python3

import os
from pathlib import Path
import sys

# need to keep this path append until this repo migrates to using ironbank-modules
sys.path.append(Path(__file__).absolute().parents[2].as_posix())

from anchore import Anchore  # pylint: disable=C0413


def main() -> None:
    """Main function for running the anchore scan.

    This function fetches credentials for the anchore scan from environment variables,
    creates an anchore object with these credentials, sets the path for storing scan results,
    and then runs the anchore scan on an image specified by the 'IMAGE_TO_SCAN' environment variable.

    anchore scan results include vulnerability data, compliance data, and version information,
    which are stored in the specified path.

    Environment Variables:
    - ANCHORE_URL: The URL for the anchore service.
    - ANCHORE_USERNAME: The username for the anchore service.
    - ANCHORE_PASSWORD: The password for the anchore service.
    - ANCHORE_VERIFY: (Optional) A boolean specifying whether to verify the SSL certificate
                      of the anchore service. Defaults to True.
    - ANCHORE_SCANS: (Optional) The path where scan results will be stored. Defaults to '/tmp/anchore_scans'.
    - IMAGE_TO_SCAN: The image on which the anchore scan will be performed.
    """
    # Get logging level, set manually when running pipeline

    anchore_scan = Anchore(
        url=os.environ["ANCHORE_URL"],
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
