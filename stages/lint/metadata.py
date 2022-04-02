#!/usr/bin/python3
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

from classes.project import CHT_Project  # noqa: E402
from classes.utils import logger  # noqa: E402
from hardening_manifest import Hardening_Manifest  # noqa: E402


def main():
    # Get logging level, set manually when running pipeline
    logLevel = os.environ.get("LOGLEVEL", "INFO").upper()
    logFormat = (
        "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s"
        if logLevel == "DEBUG"
        else "%(levelname)s: %(message)s"
    )
    log = logger.setup(name="lint.metadata", level=logLevel, format=logFormat)

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
        log.error("Hardening Manifest validation timeout exceeded.")
        log.error(
            "This is likely due to field in the hardening_manifest.yaml being invalid and \
            causing an infinite loop during validation"
        )
        log.error(
            "Please check your hardening manifest to confirm all fields have valid values"
        )
        process.terminate()
        sys.exit(1)
    elif process.exitcode != 0:
        log.error("Hardening Manifest failed jsonschema validation")
        log.error("Verify Hardening Manifest content")
        log.error(parent_conn.recv())
        sys.exit(1)
    else:
        # verify no labels have a value of fixme (case insensitive)
        log.debug("Checking for FIXME values in labels/maintainers")
        invalid_labels = hardening_manifest.reject_invalid_labels()
        invalid_maintainers = hardening_manifest.reject_invalid_maintainers()
        if invalid_labels or invalid_maintainers:
            log.error(
                "Please update these labels to appropriately describe your container \
                    before rerunning this pipeline"
            )
            sys.exit(1)
        log.info("Hardening manifest is validated")
    hardening_manifest.create_artifacts()


if __name__ == "__main__":
    main()
