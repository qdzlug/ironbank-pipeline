#!/usr/bin/python3
import json
import logging
import os
import sys
from pathlib import Path

import jsonschema
import yaml

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "../../scripts/"))


def main():
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
    dockerfile_file_path = Path("Dockerfile")
    if hardening_manifest_yaml_path.exists():
        with hardening_manifest_yaml_path.open("r") as f:
            content = yaml.safe_load(f)
            logging.debug("Checking for valid registry data in resources.")
            invalid_tags = reject_invalid_tags(content)
            if invalid_tags:
                logging.error(
                    "Please update the tags to ensure they do not contain registry1.dso.mil. This failure will change from soft to hard in January 2022."
                )
                for tag in invalid_tags:
                    logging.error(
                        f"The following tag is invalid and must be addressed: {tag}"
                    )
                sys.exit(1)
            logging.info("Hardening manifest is validated")
    else:
        logging.error(
            "hardening_manifest.yaml does not exist, please add a hardening_manifest.yaml file to your project"
        )
        logging.error("Exiting.")
        sys.exit(1)
    if dockerfile_file_path.exists():
        with dockerfile_file_path.open("r") as f:
            content = [line.rstrip() for line in f]
            logging.debug("Checking for valid final FROM statement in Dockerfile.")
            invalid_from = validate_final_from(content)
            if invalid_from:
                logging.error(
                    "The final FROM statement in the Dockerfile must be FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"
                )
                sys.exit(1)
            logging.info("Dockerfile is validated.")


def check_for_invalid_tag(subcontent: dict):
    for k, v in subcontent.items():
        if "registry1.dso.mil" in v:
            return v


def reject_invalid_tags(content: list) -> list:
    """
    Returns list of tags in the hardening manifest's resource list that are invalid, i.e. contain 'registry1.dso.mil'
    """
    logging.info("Checking tags")
    invalid_tags = []
    for x in content["resources"]:
        if "docker://" or "github://" in x["url"]:
            invalid_tag = check_for_invalid_tag(x)
            if invalid_tag:
                logging.info("Invalid tag found")
                invalid_tags.append(invalid_tag)
    return invalid_tags


def remove_non_from_statements(content: list) -> list:
    from_list = []
    for line in content:
        if "FROM" in line:
            from_list.append(line)
    return from_list


def validate_final_from(content: list):
    """
    Returns whether the final FROM statement in the Dockerfile is valid, i.e. FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}
    """
    from_list = remove_non_from_statements(content)
    if from_list[-1] != "FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}":
        return True
    else:
        return False


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


if __name__ == "__main__":
    main()
