#!/usr/bin/python3
import logging
import os
import sys
from pathlib import Path

import multiprocessing
import time


sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from classes.project import CHT_Project
from hardening_manifest import Hardening_Manifest


def main():
    # Get logging level, set manually when running pipeline

    # replace with logger
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

    cht_project = CHT_Project()
    print(os.getcwd())
    hardening_manifest = Hardening_Manifest(
        cht_project.hardening_manifest_path,
        Path(
            Path(__file__).parent.parent.parent, "schema/hardening_manifest.schema.json"
        ).as_posix(),
    )
    # Use the project description.yaml file path if one exists

    parent_conn, child_conn = multiprocessing.Pipe()
    process = multiprocessing.Process(
        target=hardening_manifest.validate_schema, args=(child_conn,)
    )
    process.start()
    # wait for two minutes unless process exits
    # if process exits, check status
    # if alive after two minutes, exit
    verification_timeout = int(os.environ.get("HM_VERIFY_TIMEOUT", 120))
    while verification_timeout:
        time.sleep(1)
        verification_timeout -= 1
        if not process.is_alive():
            break
    if process.is_alive():
        logging.error("Hardening Manifest validation timeout exceeded.")
        logging.error(
            "This is likely due to field in the hardening_manifest.yaml being invalid and causing an infinite loop during validation"
        )
        logging.error(
            "Please check your hardening manifest to confirm all fields have valid values"
        )
        process.terminate()
        sys.exit(1)
    elif process.exitcode != 0:
        logging.error("Hardening Manifest failed jsonschema validation")
        logging.error("Verify Hardening Manifest content")
        logging.error(parent_conn.recv())
        sys.exit(1)
    else:
        # verify no labels have a value of fixme (case insensitive)
        logging.debug("Checking for FIXME values in labels/maintainers")
        invalid_labels = hardening_manifest.reject_invalid_labels()
        invalid_maintainers = hardening_manifest.reject_invalid_maintainers()
        if invalid_labels or invalid_maintainers:
            logging.error(
                "Please update these labels to appropriately describe your container before rerunning this pipeline"
            )
            sys.exit(1)
        logging.info("Hardening manifest is validated")
    hardening_manifest.create_artifacts()


if __name__ == "__main__":
    main()
