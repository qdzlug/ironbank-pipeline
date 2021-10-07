#!/usr/bin/env python3
import json
import sys
import os
import logging

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from vat_container_status import is_approved


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

    vat_response = {}
    with open(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json", "r") as f:
        vat_response = json.load(f)

    approved, approval_status, approval_comments = is_approved(vat_response, True)
    if approved:
        logging.info("This container is noted as an approved image in VAT")
        logging.info(f"Container accreditation: {approval_status}")
        logging.info(f"Container accreditation comments: {approval_comments}")
    else:
        logging.error("This container is not noted as an approved image in VAT")
        logging.error(f"Container accreditation: {approval_status}")
        logging.error(f"Container accreditation comments: {approval_comments}")
        sys.exit(1)


if __name__ == "__main__":
    main()
