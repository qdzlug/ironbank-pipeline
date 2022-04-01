import logging
import os
import sys


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import CHT_Project  # noqa E402
from classes.apis import VAT_API
from hardening_manifest import Hardening_Manifest


def main() -> None:
    cht_project = CHT_Project()
    hardening_manifest = Hardening_Manifest(cht_project.hardening_manifest_path)
    vat_api = VAT_API(url=os.environ["VAT_BACKEND_SERVER_ADDRESS"])
    vat_api.check_access(image_name=hardening_manifest.image_name, create_request=True)
    logging.info("Retrieve Auth Status from VAT")
    logging.info(f"Response: {vat_api.response.text}")
    logging.debug(f"JSON Response:\n{vat_api.response.json}")


if __name__ == "__main__":
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            filename="new_vat_import_logging.out",
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    main()
