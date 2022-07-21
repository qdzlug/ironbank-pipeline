#!/usr/bin/env python3

import os
import logging
import requests
import sys


def post_artifact_data_vat():
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
            "containerName": os.environ["IMAGE_NAME"],
            "containerVersion": os.environ["IMAGE_VERSION"],
            "publishedTimestamp": os.environ["directory_date"],
            "readme": os.environ["README_PATH_SHORT"],
            "license": os.environ["LICENSE_PATH_SHORT"],
            "tar": os.environ["TAR_PATH_SHORT"],
        },
    )
    return post_resp


def main():
    if os.environ["CI_COMMIT_BRANCH"] == "master":
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

        try:
            app = "VAT"
            post_resp = post_artifact_data_vat()
            post_resp.raise_for_status()
            logging.info(f"Uploaded container data to {app} API")
        except requests.exceptions.Timeout:
            logging.exception("Unable to reach the IBFE API, TIMEOUT.")
            sys.exit(1)
        except requests.exceptions.HTTPError:
            logging.error(f"Got HTTP {post_resp.status_code}")
            logging.error(f"{app} HTTP error")
            sys.exit(1)
        except requests.exceptions.RequestException:
            logging.error(f"Error submitting container data to {app} API")
            sys.exit(1)
        except Exception:
            logging.error(f"Unhandled exception for {app}")
            sys.exit(1)
    else:
        logging.debug("Skipping use of vat artifacts and ibfe build endpoints")


if __name__ == "__main__":
    main()
