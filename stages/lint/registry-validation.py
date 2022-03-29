#!/usr/bin/python3
import json
import logging
import os
import sys
from pathlib import Path
import dockerfile

import jsonschema
import yaml


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
                    "Please update the following tags to ensure they do not contain registry1.dso.mil. This failure will change from soft to hard in January 2022."
                )
                for tag in invalid_tags:
                    logging.error(
                        f"The following tag is invalid and must be addressed: {tag}"
                    )
                sys.exit(1)
            logging.info("Hardening manifest is validated")
            if content["args"]["BASE_IMAGE"] or content["args"]["BASE_TAG"]:
                if dockerfile_file_path.exists():
                    parsed_dockerfile = parse_dockerfile("Dockerfile")
                    from_statement_list = remove_non_from_statements(parsed_dockerfile)
                    invalid_from = validate_final_from(from_statement_list)
                    if invalid_from:
                        logging.error(
                            "The final FROM statement in the Dockerfile must be FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"
                        )
                        sys.exit(1)
            logging.info("Dockerfile is validated.")
    else:
        logging.error(
            "hardening_manifest.yaml does not exist, please add a hardening_manifest.yaml file to your project"
        )
        logging.error("Exiting.")
        sys.exit(1)


def check_for_invalid_tag(subcontent: dict):
    for _, v in subcontent.items():
        if "registry1.dso.mil" in v.lower():
            return v


def reject_invalid_tags(content: dict) -> list:
    """
    Returns list of tags in the hardening manifest's resource list that are invalid, i.e. contain 'registry1.dso.mil'
    """
    logging.info("Checking tags")
    invalid_tags = []
    try:
        for x in content["resources"]:
            if x["url"].startswith("docker://") or x["url"].startswith("github://"):
                invalid_tag = check_for_invalid_tag(x)
                if invalid_tag:
                    logging.info("Invalid tag found")
                    invalid_tags.append(invalid_tag)
    except KeyError:
        logging.info("Hardening Manifest does not contain a resources section")
    return invalid_tags


def remove_non_from_statements(dockerfile_tuple: tuple) -> list:
    from_list = []
    for command in dockerfile_tuple:
        if command.cmd.lower() == "from":
            from_list.append(command)
    return from_list


def validate_final_from(content: list):
    """
    Returns whether the final FROM statement in the Dockerfile is valid, i.e. FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}
    """
    if content[-1].value[0] not in (
        "${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}",
        "$BASE_REGISTRY/$BASE_IMAGE:$BASE_TAG",
    ):
        return True
    else:
        return False


def parse_dockerfile(dockerfile_path: str):
    try:
        parsed_file = dockerfile.parse_file(dockerfile_path)
        return parsed_file
    except dockerfile.GoIOError:
        logging.error("The Dockerfile could mot be opened.")
        sys.exit(1)
    except dockerfile.GoParseError:
        logging.error("The Dockerfile is not pareseable.")
        sys.exit(1)


# def validate_yaml(content, conn):
#     logging.info("Validating schema")
#     schema_path = Path(__file__).parent / "../../schema/hardening_manifest.schema.json"
#     with schema_path.open("r") as s:
#         schema_s = s.read()
#     schema = json.loads(schema_s)
#     regex = os.environ.get("LABEL_ALLOWLIST_REGEX", None)
#     if regex:
#         schema["properties"]["labels"]["patternProperties"] = {
#             regex: {"$ref": "#/definitions/printable-characters-without-newlines"}
#         }
#     try:
#         # may hang from catastrophic backtracking if format is invalid
#         logging.info("This task will exit if not completed within 2 minutes")
#         jsonschema.validate(content, schema)
#     except jsonschema.ValidationError as ex:
#         conn.send(ex.message)
#         sys.exit(1)


if __name__ == "__main__":
    main()
