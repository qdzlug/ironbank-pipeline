#!/usr/bin/env python3

from pathlib import Path
import sys
import os
import logging
import requests
import json

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from vat_container_status import is_approved  # noqa E402


def _get_vat_response(im_name, im_version):
    logging.info("Running query to vat api")
    url = f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/p1/container"
    vat_resp = {}
    try:
        r = requests.get(
            url,
            params={
                "name": im_name,
                "tag": im_version,
            },
        )
    except requests.exceptions.RequestException:
        logging.exception(f"Could not access VAT API: {url}")
        sys.exit(1)

    if r.status_code == 200:
        logging.info("Fetched data from vat successfully")
        vat_resp = r.json()

    elif r.status_code == 404:
        logging.warning(f"{im_name}:{im_version} not found in VAT")
        logging.warning(r.text)

    elif r.status_code == 400:
        logging.warning(f"Bad request: {url}")
        logging.warning(r.text)
        sys.exit(1)

    else:
        logging.warning(f"Unknown response from VAT {r.status_code}")
        logging.warning(r.text)
        logging.warning(
            "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
        )
        sys.exit(1)
    return vat_resp


def main():
    vat_response = _get_vat_response(
        os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"]
    )
    logging.debug(f"VAT response\n{vat_response}")
    filename = Path(os.environ["ARTIFACT_DIR"], "vat_api_findings.json")
    with filename.open(mode="w") as f:
        json.dump(vat_response, f)

    approved, _, approval_status, approval_comment = is_approved(vat_response, False)
    logging.info(f"Approved: {approved}")
    logging.info(f"Approval Status: {approval_status}")
    if approval_comment:
        logging.info(f"Approval Comment: {approval_comment}")
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
