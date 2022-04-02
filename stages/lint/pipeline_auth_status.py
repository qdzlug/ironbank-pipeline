import os
import sys


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import CHT_Project  # noqa E402
from classes.utils import logger  # noqa: E402
from classes.apis import VAT_API  # noqa: E402
from hardening_manifest import Hardening_Manifest  # noqa: E402


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
    cht_project = CHT_Project()
    hardening_manifest = Hardening_Manifest(cht_project.hardening_manifest_path)
    vat_api = VAT_API(url=os.environ["VAT_BACKEND_SERVER_ADDRESS"])
    vat_api.check_access(image_name=hardening_manifest.image_name, create_request=True)
    log.info("Retrieve Auth Status from VAT")
    log.info(f"Response: {vat_api.response.text}")
    log.debug(f"JSON Response:\n{vat_api.response.json}")


if __name__ == "__main__":
    main()
