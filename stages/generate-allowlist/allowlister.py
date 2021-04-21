#!/usr/bin/env python3

import pathlib
import json
import sys
import os
import logging


def main() -> None:
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

    logging.info("Generating whitelist for Anchore")
    anchore_compliance = json.loads(
        pathlib.Path(
            os.environ["ARTIFACT_STORAGE"],
            "scan-results",
            "anchore",
            "anchore_gates.json",
        ).read_text()
    )
    anchore_security = json.loads(
        pathlib.Path(
            os.environ["ARTIFACT_STORAGE"],
            "scan-results",
            "anchore",
            "anchore_security.json",
        ).read_text()
    )
    vat_findings = json.loads(
        pathlib.Path(
            os.environ["ARTIFACT_STORAGE"], "lint", "vat_api_findings.json"
        ).read_text()
    )

    logging.info(anchore_compliance)
    logging.info(anchore_security)
    logging.info(vat_findings)


if __name__ == "__main__":
    main()
