import os
import sys


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import DsopProject  # noqa E402
from classes.utils import logger  # noqa: E402
from classes.apis import VatAPI  # noqa: E402
from hardening_manifest import HardeningManifest  # noqa: E402


def main() -> None:
    # Get logging level, set manually when running pipeline
    logLevel = os.environ.get("LOGLEVEL", "INFO").upper()
    logFormat = (
        "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s"
        if logLevel == "DEBUG"
        else "%(levelname)s: %(message)s"
    )
    log = logger.setup(
        name="lint.pipeline_auth_status", level=logLevel, format=logFormat
    )
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    vat_api = VatAPI(url=os.environ["VAT_BACKEND_SERVER_ADDRESS"])
    vat_api.check_access(image_name=hardening_manifest.image_name, create_request=True)
    log.info("Retrieve Auth Status from VAT")
    log.info(f"Response: {vat_api.response.text}")
    log.debug(f"JSON Response:\n{vat_api.response.json}")


if __name__ == "__main__":
    main()
