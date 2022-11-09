#!/usr/bin/env python3

import subprocess
import json
import sys
import os
import logging

from ironbank.pipeline.vat_container_status import is_approved


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

    _, exit_code, accreditation_status, accreditation_comments = is_approved(
        vat_response, True
    )
    logging.debug(f"EXIT CODE returned from is_approved function: {exit_code}")
    logging.debug(f"Accreditation Status: {accreditation_status}")
    logging.debug(f"Accreditation Comments: {accreditation_comments}")
    if exit_code != 0:
        logging.debug("Error: This pipeline failed the Check CVEs job")
        if os.environ["CI_COMMIT_BRANCH"] == "master":
            subprocess.run(
                [
                    f"{os.environ['PIPELINE_REPO_DIR']}/stages/check-cves/mattermost-failure-webhook.sh"
                ]
            )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()