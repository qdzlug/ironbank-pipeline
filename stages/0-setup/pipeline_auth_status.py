#!/usr/bin/env python3

import asyncio
import os
import sys

from pipeline.apis import VatAPI
from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject
from common.utils import logger

log = logger.setup(name="lint.pipeline_auth_status")


async def main() -> None:
    """Asynchronous main function to validate an image name against a VAT
    (Versioned Artifact Tracker) backend.

    The function performs the following steps:
    1. Initializes a DsopProject and a HardeningManifest object using the hardening_manifest_path from the DsopProject.
    2. Initializes a VatAPI object with the VAT_BACKEND_URL from the environment variables.
    3. Sends a check access request to the VAT backend with the image name from the hardening manifest and a VAT token from
       the environment variables.
    4. If there is no response from the VAT backend, or if the response status code is not 200, logs an error message and
       exits the program with status code 1.
    5. Logs the VAT backend response.

    Note:
    The function is designed to run in an asynchronous context and should be invoked using asyncio.run().

    Raises:
    SystemExit: The function exits with status 1 if there is no response from the VAT backend or if the response status code
                is not 200.
    """
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    vat_api = VatAPI(url=os.environ["VAT_BACKEND_URL"])

    vat_api.check_access(
        image_name=hardening_manifest.image_name,
        auth=os.environ["VAT_TOKEN"],
        create_request=True,
    )

    if not vat_api.response or vat_api.response.status_code != 200:
        log.error("Failing Pipeline")
        sys.exit(1)

    log.info("Retrieve Auth Status from VAT")
    log.info(f"Response: {vat_api.response.text}")
    log.debug(f"JSON Response:\n{vat_api.response.json}")


if __name__ == "__main__":
    asyncio.run(main())
