#!/usr/bin/python3
import json
import logging
import os
import sys
from pathlib import Path

import jsonschema
import yaml
import multiprocessing
import time

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "../../scripts/"))


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
    hardening_manifest_yaml_path = Path("hardening_manifest.yaml")
    if hardening_manifest_yaml_path.exists():
        # Use the project description.yaml file path if one exists
        with hardening_manifest_yaml_path.open("r") as f:
            content = yaml.safe_load(f)
        parent_conn, child_conn = multiprocessing.Pipe()
        process = multiprocessing.Process(
            target=validate_yaml, args=(content, child_conn)
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
            invalid_labels = reject_invalid_labels(content)
            invalid_maintainers = reject_invalid_maintainers(content)
            if invalid_labels or invalid_maintainers:
                logging.error(
                    "Please update these labels to appropriately describe your container before rerunning this pipeline"
                )
                sys.exit(1)
            logging.info("Hardening manifest is validated")
    else:
        logging.error(
            "hardening_manifest.yaml does not exist, please add a hardening_manifest.yaml file to your project"
        )
        logging.error("Exiting.")
        sys.exit(1)
    process_yaml(content)


def check_for_fixme(subcontent: dict) -> list:
    """
    Returns list of keys in dictionary whose value contains FIXME (case insensitve)
    """
    return [
        k
        for (k, v) in subcontent.items()
        if isinstance(v, (str)) and "fixme" in v.lower()
    ]


def reject_invalid_labels(content: dict) -> list:
    """
    Returns list of keys in hardening manifest labels whose value contains FIXME (case insensitve)
    """
    logging.info("Checking label values")
    invalid_labels = check_for_fixme(content["labels"])
    for k in invalid_labels:
        logging.error(f"FIXME found in {k}")
    return invalid_labels


def reject_invalid_maintainers(content: dict) -> list:
    """
    Returns list of keys in hardening manifest maintainers whose value contains FIXME (case insensitve)
    """
    logging.info("Checking maintainer values")
    invalid_maintainers = []
    for maintainer in content["maintainers"]:
        invalid_maintainers += check_for_fixme(maintainer)
    for k in invalid_maintainers:
        logging.error(f"FIXME found in {k}")
    return invalid_maintainers


def validate_yaml(content, conn):
    logging.info("Validating schema")
    schema_path = Path(__file__).parent / "../../schema/hardening_manifest.schema.json"
    with schema_path.open("r") as s:
        schema_s = s.read()
    schema = json.loads(schema_s)
    regex = os.environ.get("LABEL_ALLOWLIST_REGEX", None)
    if regex:
        schema["properties"]["labels"]["patternProperties"] = {
            regex: {"$ref": "#/definitions/printable-characters-without-newlines"}
        }
    try:
        # may hang from catastrophic backtracking if format is invalid
        logging.info("This task will exit if not completed within 2 minutes")
        jsonschema.validate(content, schema)
    except jsonschema.ValidationError as ex:
        conn.send(ex.message)
        sys.exit(1)


def process_yaml(content):
    artifact_dir = Path(os.environ["ARTIFACT_DIR"])

    with (artifact_dir / "variables.env").open("w") as f:
        f.write(f"IMAGE_NAME={content['name']}\n")
        f.write(f"IMAGE_VERSION={content['tags'][0]}\n")

    with (artifact_dir / "tags.txt").open("w") as f:
        for tag in content["tags"]:
            f.write(tag)
            f.write("\n")

    with (artifact_dir / "args.env").open("w") as f:
        for key, value in content["args"].items():
            f.write(f"{key}={value}\n")

    with (artifact_dir / "labels.env").open("w") as f:
        for key, value in content["labels"].items():
            f.write(f"{key}={value}\n")

    # optional field,if keywords key in yaml, create file. source_values() in create_repo_map checks if file exists, if not pass empty list
    if "mil.dso.ironbank.image.keywords" in content["labels"]:
        with (artifact_dir / "keywords.txt").open("w") as f:
            labels = [
                k.strip()
                for k in content["labels"]["mil.dso.ironbank.image.keywords"].split(",")
            ]
            for label in labels:
                f.write(label)
                f.write("\n")
    else:
        logging.info("Keywords field does not exist in hardening_manifest.yaml")

    # "resources" intentionally left out

    # Maintainers field is used for POC information and won't be parsed


if __name__ == "__main__":
    main()
