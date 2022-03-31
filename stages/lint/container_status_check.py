#!/usr/bin/env python3
from pathlib import Path
import sys
import os
import logging
import json

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import CHT_Project
from classes.apis import VAT_API
from hardening_manifest import Hardening_Manifest
from vat_container_status import is_approved


def main():
    # approval_status, approval_text = _get_vat_findings_api(
    #     os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"]
    # )
    cht_project = CHT_Project()
    hardening_manifest = Hardening_Manifest(cht_project.hardening_manifest_path)
    vat_api = VAT_API(url=f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}")
    vat_response = vat_api._get_container(
        vat_api,
        image_name=hardening_manifest.image_name,
        image_tag=hardening_manifest.image_tag,
    )

    logging.debug(f"VAT response\n{vat_response}")
    filename = Path(os.environ["ARTIFACT_DIR"], "vat_api_findings.json")
    with filename.open(mode="w") as f:
        json.dump(vat_response, f)

    approved, _, approval_status, approval_comment = is_approved(vat_response, False)
    approval_status = approval_status.lower().replace(" ", "_")
    logging.debug("updated Approval Status: {approval_status}")

    filename = Path(os.environ["ARTIFACT_DIR"], "image_approval.json")
    image_approval = {
        "IMAGE_APPROVAL_STATUS": approval_status,
        "IMAGE_APPROVAL_TEXT": approval_comment,
    }
    with filename.open(mode="w") as f:
        json.dump(image_approval, f)

    if approved:
        logging.info("This container is noted as an approved image in VAT")
    elif os.environ["CI_COMMIT_BRANCH"] != "master":
        logging.warning("This container is not noted as an approved image in VAT")
    else:
        logging.error("This container is not noted as an approved image in VAT")
        logging.error("Failing pipeline")
        sys.exit(1)


if __name__ == "__main__":
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
    main()
