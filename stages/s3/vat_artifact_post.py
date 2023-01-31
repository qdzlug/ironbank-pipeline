#!/usr/bin/env python3

import os
import sys
import requests
from ironbank.pipeline.utils import logger

log = logger.setup("vat_artifact_post")


def post_artifact_data_vat():
    """
    POST to VAT's artifacts endpoint to allow IBFE to start displaying the published image data
    """
    vat_endpoint = (
        f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/internal/import/artifacts"
    )
    post_resp = requests.post(
        vat_endpoint,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['CI_JOB_JWT_V2']}",
        },
        json={
            "imageName": os.environ["IMAGE_NAME"],
            "tag": os.environ["IMAGE_VERSION"],
            "publishedTimestamp": os.environ["directory_date"],
            "readme": "NONE",
            "license": "NONE",
            "tar": os.environ["TAR_PATH_SHORT"],
        },
        timeout=None,
    )
    return post_resp


def main():
    try:
        post_resp = post_artifact_data_vat()
        post_resp.raise_for_status()
        log.info("Uploaded container data to VAT API")
    except requests.exceptions.RequestException as req_exc:
        log.error("Error submitting container data to VAT API")
        if isinstance(req_exc, requests.exceptions.Timeout):
            log.exception("Unable to reach the VAT API, TIMEOUT.")
        if isinstance(req_exc, requests.exceptions.HTTPError):
            log.error("Got HTTP %s", post_resp.status_code)
            log.error("VAT HTTP error")
        sys.exit(1)


if __name__ == "__main__":
    main()
