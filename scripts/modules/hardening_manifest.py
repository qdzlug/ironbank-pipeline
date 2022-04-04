#!/usr/bin/env python3
import os
import sys
import json
import yaml
import jsonschema
from pathlib import Path
import multiprocessing

from utils import logger

# Keeping global until other methods get pulled into class in this file
log = logger.setup(name="hardening_manifest")


# Not using dataclass because post_init is required for file load and parameter initialization
class HardeningManifest:
    def __init__(self, hm_path: str, schema_path: str = "./"):
        self.hm_path: Path = Path(hm_path)
        self.schema_path: Path = Path(schema_path)
        with self.hm_path.open("r") as f:
            tmp_content: dict = yaml.safe_load(f)
        self.image_name: str = tmp_content["name"]
        # validation done in hardening manifest schema
        self.image_tags: list[str] = tmp_content["tags"]
        # added for clarity over what tag will be used to publish
        self.image_tag: str = self.image_tags[0]
        self.args: dict = tmp_content["args"]
        # added for clarity for required args
        self.base_image_name: str = self.args["BASE_IMAGE"]
        self.base_image_tag: str = self.args["BASE_TAG"]
        # TODO: define labels type
        self.labels: dict = tmp_content["labels"]
        # TODO: define resources type
        self.resources: list[dict] = tmp_content.get("resources", [])
        self.maintainers: list[dict] = tmp_content["maintainers"]

    def validate_schema(self, conn: multiprocessing.Pipe):
        log.info("Validating schema")
        with self.hm_path.open("r") as f:
            hm_content = yaml.safe_load(f)
        with self.schema_path.open("r") as f:
            schema_content = json.load(f)
        label_regex = os.environ.get("LABEL_ALLOWLIST_REGEX", None)
        if label_regex:
            schema_content["properties"]["labels"]["patternProperties"] = {
                label_regex: {
                    "$ref": "#/definitions/printable-characters-without-newlines"
                }
            }
        try:
            # may hang from catastrophic backtracking if format is invalid
            log.info("This task will exit if not completed within 2 minutes")
            jsonschema.validate(hm_content, schema_content)
        except jsonschema.ValidationError as ex:
            conn.send(ex.message)
            sys.exit(1)

    def check_for_fixme(self, subcontent: dict) -> list:
        """
        Returns list of keys in dictionary whose value contains FIXME (case insensitve)
        """
        return [
            k
            for (k, v) in subcontent.items()
            if isinstance(v, (str)) and "fixme" in v.lower()
        ]

    def reject_invalid_labels(self) -> list:
        """
        Returns list of keys in hardening manifest labels whose value contains FIXME (case insensitve)
        """
        log.info("Checking label values")
        invalid_labels = self.check_for_fixme(self.labels)
        for k in invalid_labels:
            log.error(f"FIXME found in {k}")
        return invalid_labels

    def check_for_invalid_image_source(self, subcontent: dict):
        for v in subcontent.values():
            if "registry1.dso.mil" in v.lower():
                return v

    def reject_invalid_image_sources(self) -> list:
        """
        Returns list of tags in the hardening manifest's resource list that are invalid, i.e. contain 'registry1.dso.mil'
        """
        log.info("Checking tags")
        invalid_sources = []
        for x in self.resources:
            if x["url"].startswith("docker://") or x["url"].startswith("github://"):
                invalid_source = self.check_for_invalid_image_source(x)
                if invalid_source:
                    log.info("Invalid tag found")
                    invalid_sources.append(invalid_source)
        return invalid_sources

    def reject_invalid_maintainers(self) -> list:
        """
        Returns list of keys in hardening manifest maintainers whose value contains FIXME (case insensitve)
        """
        log.info("Checking maintainer values")
        invalid_maintainers = []
        for maintainer in self.maintainers:
            invalid_maintainers += self.check_for_fixme(maintainer)
        for k in invalid_maintainers:
            log.error(f"FIXME found in {k}")
        return invalid_maintainers

    # TODO: Deprecate this once CI variables are replaced by modules with reusable methods
    def create_artifacts(self):
        artifact_dir = Path(os.environ["ARTIFACT_DIR"])
        self.create_env_var_artifacts(artifact_dir)
        self.create_tags_artifact(artifact_dir)
        self.create_keywords_artifact(artifact_dir)

    def create_env_var_artifacts(self, artifact_dir: Path) -> None:
        with (artifact_dir / "variables.env").open("w") as f:
            f.write(f"IMAGE_NAME={self.image_name}\n")
            f.write(f"IMAGE_VERSION={self.image_tag}\n")
            f.write(f"BASE_IMAGE={self.base_image_name}\n")
            f.write(f"BASE_TAG={self.base_image_tag}")
            log.debug(f"IMAGE_NAME={self.image_name}\nIMAGE_VERSION={self.image_tag}")
            log.debug(
                f"BASE_IMAGE={self.base_image_name}\nBASE_TAG={self.base_image_tag}"
            )
        with (artifact_dir / "args.env").open("w") as f:
            for key, value in self.args.items():
                f.write(f"{key}={value}\n")
        with (artifact_dir / "labels.env").open("w") as f:
            for key, value in self.labels.items():
                f.write(f"{key}={value}\n")

    def create_tags_artifact(self, artifact_dir: Path) -> None:
        with (artifact_dir / "tags.txt").open("w") as f:
            for tag in self.image_tags:
                f.write(tag)
                f.write("\n")

    def create_keywords_artifact(self, artifact_dir: Path) -> None:
        # optional field,if keywords key in yaml, create file. source_values() in create_repo_map checks if file exists, if not pass empty list
        if "mil.dso.ironbank.image.keywords" in self.labels:
            with (artifact_dir / "keywords.txt").open("w") as f:
                labels = [
                    k.strip()
                    for k in self.labels["mil.dso.ironbank.image.keywords"].split(",")
                ]
                for label in labels:
                    f.write(label)
                    f.write("\n")
        else:
            log.info("Keywords field does not exist in hardening_manifest.yaml")

    # define dict() method and use for __repr__ and __str__

    def __repr__(self) -> str:
        return f"{self.image_name}:{self.image_tag}"

    def __str__(self) -> str:
        return f"{self.image_name}:{self.image_tag}"


# TODO: (modularization effort) move these into class as we refactor code in other stages
# Get values generated by process_yaml() in metadata.py
# Currently used to retrieve keywords and tags
def source_values(source_file, key) -> list:
    num_vals = 0
    val_list = []
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            for line in sf:
                val_entry = line.strip()
                val_list.append(val_entry)
                num_vals += 1
        log.info(f"Number of {key} detected: {num_vals}")
    else:
        log.info(source_file + " does not exist")
    return val_list


def get_source_keys_values(source_file) -> dict:
    """
    Returns the labels from the hardening_manifest.yaml file as dictionary.
    Ignore keywords since IBFE already has an implementation for gathering keywords

    """
    hm_labels = {}
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            for line in sf:
                key, value = line.rstrip().split("=", 1)
                if key != "mil.dso.ironbank.image.keywords":
                    hm_labels[key] = value
    return hm_labels


def get_approval_status(source_file) -> tuple[str, str]:
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            approval_object = json.load(sf)
    approval_status = approval_object["IMAGE_APPROVAL_STATUS"]
    approval_text = approval_object["IMAGE_APPROVAL_TEXT"]
    return approval_status, approval_text
