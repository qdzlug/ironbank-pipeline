#!/usr/bin/env python3

import os
from pathlib import Path

from ironbank_py39_modules.scanner_api_handlers.anchore import Anchore


def main() -> None:
    """Main function for running the Anchore scan.

    This function fetches credentials for the Anchore scan from environment variables,
    creates an Anchore object with these credentials, sets the path for storing scan results,
    and then runs the Anchore scan on an image specified by the 'IMAGE_TO_SCAN' environment variable.

    Anchore scan results include vulnerability data, compliance data, and version information,
    which are stored in the specified path.

    Environment Variables:
    - ANCHORE_URL: The URL for the Anchore service.
    - ANCHORE_USERNAME: The username for the Anchore service.
    - ANCHORE_PASSWORD: The password for the Anchore service.
    - ANCHORE_VERIFY: (Optional) A boolean specifying whether to verify the SSL certificate
                      of the Anchore service. Defaults to True.
    - ANCHORE_SCANS: (Optional) The path where scan results will be stored. Defaults to '/tmp/anchore_scans'.
    - IMAGE_TO_SCAN: The image on which the Anchore scan will be performed.
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
