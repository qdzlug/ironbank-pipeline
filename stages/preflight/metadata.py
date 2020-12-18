#!/usr/bin/python3
import json
import logging
import os
import sys
from pathlib import Path

import jsonschema
import yaml

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "../../scripts/"))
import hardening_manifest_yaml.generate  # noqa: E402


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
        validate_yaml(content)
    else:
        # Use the generated description.yaml file path if not
        logging.warning("hardening_manifest.yaml does not exist, autogenerating")
        project_path = os.environ["CI_PROJECT_PATH"].split("/")
        assert len(project_path) > 2 and project_path[0] == "dsop"
        greylist_path = "/".join((*project_path[1:], f"{project_path[-1]}.greylist"))
        hardening_manifest_yaml_string = hardening_manifest_yaml.generate.generate(
            greylist_path=greylist_path,
            repo1_url="https://repo1.dsop.io/",
            dccscr_whitelists_branch=os.environ["WL_TARGET_BRANCH"],
            log_to_console=True,
            branch=os.environ["CI_COMMIT_BRANCH"],
        )
        generated_file = Path(os.environ["ARTIFACT_DIR"], "hardening_manifest.yaml")
        generated_file.write_text(hardening_manifest_yaml_string)
        content = yaml.safe_load(hardening_manifest_yaml_string)
        # Generated hardening_manifest.yaml is already validated

    process_yaml(content)


def validate_yaml(content):
    logging.info("Validating schema")
    schema_path = Path(__file__).parent / "../../schema/hardening_manifest.schema.json"
    with schema_path.open("r") as s:
        schema_s = s.read()
    schema = json.loads(schema_s)
    jsonschema.validate(content, schema)


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