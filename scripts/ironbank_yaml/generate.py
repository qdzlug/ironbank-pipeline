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
logger = logging.getLogger("ironbank_yaml.generate")


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
        metadata["image_name"]
        metadata["image_parent_name"]
        metadata["image_parent_tag"]
        metadata["container_owner"]
    except KeyError as e:
        logger.exception("Malformed greylist file")
        raise e

    return metadata


def _build_ironbank_yaml(metadata):
    """
    Construct the ironbank.yaml file using the metadata collected from the
    greylist and download.yaml files. Build up a string that represents the
    yaml file and then validate agains the ironbank yaml schema.

    """

    ironbank_yaml = f"""---
# Schema version of ironbank.yaml
apiVersion: v1

# Name matches the repository name in registry1
name: "{metadata["image_name"]}"

# List of tags to push for the repository in registry1
tags:
- "latest"
"""

    # Add the version to the tag list
    if "version" in metadata and metadata["version"] != "latest":
        ironbank_yaml += f'- "{metadata["version"]}"\n'

    ironbank_yaml += f"""
# Arguments to inject to the build context
args:
  BASE_IMAGE_NAME: "{metadata["image_parent_name"]}"
  BASE_IMAGE_TAG: "{metadata["image_parent_tag"]}"

# Labels to apply to the image
labels:
  org.opencontainers.image.title: "{metadata["image_name"].split("/")[-1]}"
  # FIXME: Human-readable description of the software packaged in the image
  org.opencontainers.image.description: ""
  # FIXME: License(s) under which contained software is distributed
  org.opencontainers.image.licenses: ""
  # FIXME: URL to find more information on the image
  org.opencontainers.image.url: ""
  # FIXME: Name of the distributing entity, organization or individual
  org.opencontainers.image.vendor: ""
"""
    if "version" in metadata:
        ironbank_yaml += f'  org.opencontainers.image.version: "{metadata["version"]}"'
    else:
        ironbank_yaml += "  # FIXME: Version of the packaged software\n"
        ironbank_yaml += '  org.opencontainers.image.version: ""'

    ironbank_yaml += f"""
  # FIXME: Keywords to help with search (ex. "cicd,gitops,golang")
  io.dsop.ironbank.image.keywords: ""
  # FIXME: This value can be "opensource" or "commercial"
  io.dsop.ironbank.image.type: ""
  # FIXME: Product the image belongs to for grouping multiple images
  io.dsop.ironbank.product.name: ""
  maintainer: "ironbank@dsop.io"

# List of resources to make available to the offline build context
"""

    if "resources" in metadata:
        ironbank_yaml += "resources:\n"
        ironbank_yaml += yaml.dump(metadata["resources"]).strip()
    else:
        ironbank_yaml += "resources: []"

    ironbank_yaml += f"""

# FIXME: Fill in the following details for the current container owner in the whitelist
# FIXME: Include any other vendor information if applicable
# NOTE: Uncomment or add `cht_member: true` if the maintainer is a member of CHT
# List of project maintainers
# New issues may automatically be assigned to project maintainers
maintainers:
  # FIXME: Include the name of the current container owner
- name: ""
  # FIXME: Include the gitlab username of the current container owner
  username: ""
  email: "{metadata["container_owner"]}"
#   cht_member: true
# - name: "FIXME"
#   username: "FIXME"
#   email: "FIXME"
"""

    logger.info("Validating schema")
    schema_path = os.path.join(
        os.path.dirname(__file__), "../../schema/ironbank.schema.json"
    )
    with open(schema_path, "r") as s:
        schema_s = s.read()
        try:
            schema = json.loads(schema_s)
        except json.JSONDecodeError as e:
            raise e

        try:
            ib = yaml.safe_load(ironbank_yaml)
        except yaml.YAMLError as e:
            raise e

        try:
            jsonschema.validate(ib, schema)
        except jsonschema.exceptions.ValidationError as e:
            raise e

    logger.info("Passed schema validation")
    return ironbank_yaml


def generate(greylist_path, repo1_url, dccscr_whitelists_branch="master", group="dsop"):
    """
    Generate the ironbank.yaml file using information from:
    - greylist
    - download.{yaml,json}
    - Jenkinsfile

    The generated file is returned as a string. It will represent the contents
    of the ironbank.yaml file and contain comments indicating where information
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
    return _build_ironbank_yaml(metadata)


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
