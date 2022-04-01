#!/usr/bin/python3
import logging
import os
import sys
from pathlib import Path
import dockerfile

import yaml

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)


from classes.project import CHT_Project
from hardening_manifest import Hardening_Manifest


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
    cht_project = CHT_Project()
    hardening_manifest = Hardening_Manifest(cht_project.hardening_manifest_path)

    logging.debug("Checking for valid registry data in resources.")
    invalid_tags = hardening_manifest.reject_invalid_image_sources()
    if invalid_tags:
        logging.error(
            "Please update the following tags to ensure they do not contain registry1.dso.mil.å"
        )
        for tag in invalid_tags:
            logging.error(f"The following tag is invalid and must be addressed: {tag}")
        sys.exit(1)
    logging.info("Hardening manifest is validated")
    if hardening_manifest.base_image_name or hardening_manifest.base_image_tag:
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
        logging.error("The Dockerfile could not be opened.")
        sys.exit(1)
    except dockerfile.GoParseError:
        logging.error("The Dockerfile is not parseable.")
        sys.exit(1)


if __name__ == "__main__":
    main()
