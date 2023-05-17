#!/usr/bin/env python3

import os
import sys
import asyncio

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger
from ironbank.pipeline.apis import VatAPI
from ironbank.pipeline.hardening_manifest import HardeningManifest

log = logger.setup(name="lint.pipeline_auth_status")


async def main() -> None:
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    vat_api = VatAPI(url=os.environ["VAT_BACKEND_URL"])
    vat_token = os.environ["VAT_TOKEN"]

    vat_api.check_access(
        image_name=hardening_manifest.image_name,
        auth=vat_token,
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
