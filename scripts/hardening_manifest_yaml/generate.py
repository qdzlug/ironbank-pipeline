#!/usr/bin/env python3

import re
import sys
import yaml
import json
import logging
import requests
import os
import jsonschema


logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("hardening_manifest_yaml.generate")


class FileNotFound(Exception):
    pass


def _fetch_file(url, file, branch="development"):
    """
    Grabs a raw file from gitlab.

    """
    url = f"{url}/-/raw/{branch}/{file}"

    logger.debug(url)

    try:
        r = requests.get(url=url)
    except requests.exceptions.RequestException as e:
        raise e

    if r.status_code == 200:
        return r.text


def _pluck_version(jenkinsfile):
    """
    Pluck out the version string from the Jenkinsfile using regex

    """
    version_regex = r"(?<=version:)[ \t]+((?<![\\])['\"])((?:.(?!(?<![\\])\1))*.?)"

    v = re.search(version_regex, jenkinsfile)

    # Python re module does not support dynamic length for a look-behind
    # no capture expression so the spaces (that I found at least) so the
    # leading spaces will be captured. Also the beginning quote is used
    # as the back-reference group so it will be captured. Strip the
    # whitespace and remove the beginning quote.
    if v is not None:
        v = v.group().strip()[1:]
        logger.debug(f"Discovered version: {v}")

    return v


def _prepare_data(greylist, download, jenkinsfile=None):
    """
    Load all the files into Python dictionaries and then smash them all together
    into a metadata dictionary. Perform some validation of the data that was
    gathered and then return the metadata.

    """
    metadata = dict()

    greylist_dict = None
    try:
        greylist_dict = json.loads(greylist)
        greylist_dict.pop("whitelisted_vulnerabilities")
    except KeyError:
        # Pass if no whitelisted_vulnerabilities found
        pass
    except json.JSONDecodeError as e:
        raise e

    metadata.update(greylist_dict)

    # Handle the case where download.{yaml,json} is missing
    if download is not None:
        download_dict = None
        try:
            download_dict = json.loads(download)
        except json.JSONDecodeError:
            pass

        if download_dict is None:
            try:
                download_dict = yaml.safe_load(download)
            except yaml.YAMLError:
                pass

        if download_dict is not None and download_dict["resources"] is not None:
            metadata.update(download_dict)

    version = None
    if jenkinsfile is not None:
        version = _pluck_version(jenkinsfile)
        if version is not None:
            metadata.update({"version": version})

    try:
        assert "image_name" in metadata
        assert "image_parent_name" in metadata
        assert "image_parent_tag" in metadata
        assert "container_owner" in metadata
    except KeyError as e:
        logger.exception("Malformed greylist file")
        raise e

    return metadata


def _build_hardening_manifest_yaml(metadata):
    """
    Construct the hardening_manifest.yaml file using the metadata collected from the
    greylist and download.yaml files. Build up a string that represents the
    yaml file and then validate agains the hardening_manifest.yaml schema.

    """

    hardening_manifest_yaml = f"""---
apiVersion: v1

# The repository name in registry1, excluding /ironbank/
name: "{metadata["image_name"]}"

# List of tags to push for the repository in registry1
# The most specific version should be the first tag and will be shown
# on ironbank.dsop.io
tags:
"""

    # Add the version to the tag list
    if "version" in metadata and metadata["version"] != "latest":
        hardening_manifest_yaml += f'- "{metadata["version"]}"'

    hardening_manifest_yaml += f"""
- "latest"

# Build args passed to Dockerfile ARGs
args:
  BASE_IMAGE: "{metadata["image_parent_name"]}"
  BASE_TAG: "{metadata["image_parent_tag"]}"

# Docker image labels
labels:
  org.opencontainers.image.title: "{metadata["image_name"].split("/")[-1]}"
  ## Human-readable description of the software packaged in the image
  # org.opencontainers.image.description: "FIXME"
  ## License(s) under which contained software is distributed
  # org.opencontainers.image.licenses: "FIXME"
  ## URL to find more information on the image
  # org.opencontainers.image.url: "FIXME"
  ## Name of the distributing entity, organization or individual
  # org.opencontainers.image.vendor: "FIXME"
"""
    if "version" in metadata:
        hardening_manifest_yaml += (
            f'  org.opencontainers.image.version: "{metadata["version"]}"'
        )
    else:
        hardening_manifest_yaml += "  ## Version of the packaged software\n"
        hardening_manifest_yaml += '  # org.opencontainers.image.version: "FIXME"'

    hardening_manifest_yaml += """
  ## Keywords to help with search (ex. "cicd,gitops,golang")
  # mil.dso.ironbank.image.keywords: "FIXME"
  ## This value can be "opensource" or "commercial"
  # mil.dso.ironbank.image.type: "FIXME"
  ## Product the image belongs to for grouping multiple images
  # mil.dso.ironbank.product.name: "FIXME"

# List of resources to make available to the offline build context
"""

    if "resources" in metadata:
        hardening_manifest_yaml += "resources:\n"
        hardening_manifest_yaml += yaml.dump(metadata["resources"]).strip()
    else:
        hardening_manifest_yaml += "resources: []"

    hardening_manifest_yaml += f"""

# List of project maintainers
# FIXME: Fill in the following details for the current container owner in the whitelist
# FIXME: Include any other vendor information if applicable
maintainers:
- email: "{metadata["container_owner"]}"
#   # The name of the current container owner
#   name: "FIXME"
#   # The gitlab username of the current container owner
#   username: "FIXME"
#   cht_member: true # FIXME: Uncomment if the maintainer is a member of CHT
# - name: "FIXME"
#   username: "FIXME"
#   email: "FIXME"
"""

    logger.info("Validating schema")
    schema_path = os.path.join(
        os.path.dirname(__file__), "../../schema/hardening_manifest.schema-relaxed.json"
    )
    with open(schema_path, "r") as s:
        schema_s = s.read()
        try:
            schema = json.loads(schema_s)
        except json.JSONDecodeError as e:
            raise e

        try:
            ib = yaml.safe_load(hardening_manifest_yaml)
        except yaml.YAMLError as e:
            raise e

        try:
            jsonschema.validate(ib, schema)
        except jsonschema.exceptions.ValidationError as e:
            raise e

    logger.info("Passed schema validation")
    return hardening_manifest_yaml


def generate(greylist_path, repo1_url, dccscr_whitelists_branch="master", group="dsop"):
    """
    Generate the hardening_manifest.yaml file using information from:
    - greylist
    - download.{yaml,json}
    - Jenkinsfile

    The generated file is returned as a string. It will represent the contents
    of the hardening_manifest.yaml file and contain comments indicating where information
    should be added or changed.

    """
    project_path = "/".join(greylist_path.split("/")[:-1])

    project_url = f"{repo1_url}/{group}/{project_path}"
    greylist_url = f"{repo1_url}/{group}/dccscr-whitelists"

    try:
        greylist = None
        download = None
        jenkinsfile = None

        greylist = _fetch_file(
            url=greylist_url,
            file=greylist_path,
            branch=dccscr_whitelists_branch,
        )
        if greylist is None:
            raise FileNotFound("Did not find greylist")

        download = _fetch_file(
            url=project_url, file="download.json", branch="development"
        )

        if download is None:
            download = _fetch_file(
                url=project_url, file="download.yaml", branch="development"
            )

        try:
            jenkinsfile = _fetch_file(
                url=project_url, file="Jenkinsfile", branch="development"
            )
        except requests.exceptions.RequestException:
            pass

    except FileNotFound as e:
        raise e

    except requests.exceptions.RequestException as e:
        raise e

    metadata = _prepare_data(greylist, download, jenkinsfile)
    return _build_hardening_manifest_yaml(metadata)


#
#   Main function used for testing
#
if __name__ == "__main__":
    test_set = [
        # "anchore/enterprise/enterprise/enterprise.greylist",
        # "redhat/ubi/ubi8/ubi8.greylist",
        # "opensource/mattermost/mattermost/mattermost.greylist",
        # "atlassian/jira-data-center/jira-node/jira-node.greylist",
        # "gitlab/gitlab/alpine-certificates/alpine-certificates.greylist",
        # "hashicorp/packer/packer/packer.greylist",
        # "google/distroless/cc/cc.greylist",
        # "oracle/oraclelinux/obi8/obi8.greylist",
        # Begin schema violations
        # Old schema - validation is an array not object
        # "cloudfit/rabbitmq/rabbitmq/rabbitmq.greylist",
        "kong/kong/kongee/kongee.greylist",
        # This one is weird, it has a greylist but doesn't look like an ib container
        "redhat/scanning-reports/reportengine/reportengine.greylist",
        # # These have duplicate items in download.yaml
        # "kubeflow/kfserving-0.2.2/xgbserver-0.2.2/xgbserver-0.2.2.greylist",
        # "kubeflow/katib/suggestion-nasrl-57c6abf76193/suggestion-nasrl-57c6abf76193.greylist",
        "security-compass/jitt/nginx/nginx.greylist",
        "security-compass/sd-elements/memcached/memcached.greylist",
        "security-compass/sd-elements/mod_wsgi/mod_wsgi.greylist",
    ]
    for greylist_path in test_set:
        logger.info(f"Processing {greylist_path}")
        print(
            generate(
                greylist_path=greylist_path,
                repo1_url="https://repo1.dsop.io",
            )
        )
