import os
import sys
import asyncio

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from project import DsopProject  # noqa E402
from utils import logger  # noqa: E402
from apis import VatAPI  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402

log = logger.setup(name="lint.pipeline_auth_status")


async def main() -> None:
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    vat_api = VatAPI(url=os.environ["VAT_BACKEND_SERVER_ADDRESS"])

    vat_api.check_access(image_name=hardening_manifest.image_name, create_request=True)

    if not vat_api.response or vat_api.response.status_code not in [200]:
        log.error("Failing Pipeline")
        sys.exit(1)

    log.info("Retrieve Auth Status from VAT")
    log.info(f"Response: {vat_api.response.text}")
    log.debug(f"JSON Response:\n{vat_api.response.json}")


if __name__ == "__main__":
    asyncio.run(main())
