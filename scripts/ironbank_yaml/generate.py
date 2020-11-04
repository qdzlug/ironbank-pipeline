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


def _fetch_file(url, file, branch):
    url = f"{url}/-/raw/{branch}/{file}"

    logger.debug(url)

    try:
        r = requests.get(url=url)
    except requests.exceptions.RequestException as e:
        raise e

    if r.status_code == 200:
        return r.text


def _parse_jenkins(jenkinsfile):
    version_regex = r"(?<=version:)[ \t]+((?<![\\])['\"])((?:.(?!(?<![\\])\1))*.?)"

    v = re.search(version_regex, jenkinsfile)

    # Python re module does not support dynamic length for a look-behind
    # no capture expression so the spaces (that I found at least) so the
    # leading spaces will be captured. Also the beginning quote is used
    # as the back-reference group so it will be captured. Strip the
    # whitespace and remove the beginning quote.
    v = v.group().strip()[1:]

    logger.debug(f"Discovered version: {v}")
    return v


def _prepare_data(greylist, download, jenkinsfile=None):
    return_dict = dict()

    greylist_dict = None
    try:
        greylist_dict = json.loads(greylist)
        greylist_dict.pop("whitelisted_vulnerabilities")
    except json.JSONDecodeError as e:
        raise e

    return_dict.update(greylist_dict)

    download_dict = None
    try:
        download_dict = json.loads(download)
    except json.JSONDecodeError:
        pass

    if download_dict is None:
        try:
            download_dict = yaml.safe_load(download)
        except yaml.YAMLError as e:
            raise e

    return_dict.update(download_dict)

    version = None
    if jenkinsfile is not None:
        version = _parse_jenkins(jenkinsfile)
        if version is not None:
            return_dict.update({"version": version})

    return return_dict


def _build_ironbank_yaml(data):
    ironbank_yaml = f"""
# Schema version of ironbank.yaml
apiVersion: v1

# Name matches the repository name in registry1
name: "{data["image_name"]}"

# List of tags to push for the repository in registry1
tags:
- "latest"
- "{data["version"]}"

# Arguments to inject to the build context
args:
  BASE_IMAGE_NAME: "{data["image_parent_name"]}"
  BASE_IMAGE_TAG: "{data["image_parent_tag"]}"

# Labels to apply to the image
labels:
  org.opencontainers.image.title: "{data["image_name"].split("/")[-1]}"
  # TODO: Human-readable description of the software packaged in the image
  org.opencontainers.image.description: ""
  # TODO: License(s) under which contained software is distributed
  org.opencontainers.image.licenses: ""
  # TODO: URL to find more information on the image
  org.opencontainers.image.url: ""
  # TODO: Name of the distributing entity, organization or individual
  org.opencontainers.image.vendor: ""
  org.opencontainers.image.version: "{data["version"]}"
  # TODO: Keywords to help with search (ex. "cicd,gitops,golang")
  io.dsop.ironbank.image.keywords: ""
  # TODO: This value can be "opensource" or "commercial"
  io.dsop.ironbank.image.type: ""
  io.dsop.ironbank.product.name: "{data["image_name"].split("/")[0]}"
  maintainer: "ironbank@dsop.io"

# List of resources to make available to the offline build context
resources:
{yaml.dump(data["resources"]).strip()}

# TODO: Fill in the following details for the current container owner in the whitelist
# TODO: Include any other vendor information if applicable
# NOTE: Uncomment or add `cht_member: true` if the maintainer is a member of CHT
# List of project maintainers
# New issues may automatically be assigned to project maintainers
maintainers:
  # TODO: Include the name of the current container owner
- name: ""
  # TODO: Include the gitlab username of the current container owner
  username: ""
  email: "{data["container_owner"]}"
#   cht_member: true
# - name: "TODO"
#   username: "TODO"
#   email: "TODO"
"""
    logger.info("Validating schema")
    try:
        ib = yaml.safe_load(ironbank_yaml)
    except yaml.YAMLError as e:
        raise e

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
            jsonschema.validate(ib, schema)
        except jsonschema.exceptions.ValidationError as e:
            raise e

    logger.info("Passed schema validation")
    return ironbank_yaml


def generate(greylist_path, repo1_url, dccscr_whitelists_branch="master", group="dsop"):
    project_path = "/".join(greylist_path.split("/")[:-1])

    project_url = f"{repo1_url}/{group}/{project_path}"
    greylist_url = f"{repo1_url}/{group}/dccscr-whitelists"

    try:
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

        if download is None:
            raise FileNotFound("Did not find download.{yaml,json}")

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

    data = _prepare_data(greylist, download, jenkinsfile)
    return _build_ironbank_yaml(data)


if __name__ == "__main__":
    greylist_path = "anchore/enterprise/enterprise/enterprise.greylist"
    logger.info(f"Processing {greylist_path}")
    print(
        generate(
            greylist_path=greylist_path,
            repo1_url="https://repo1.dsop.io",
        )
    )
    greylist_path = "redhat/ubi/ubi8/ubi8.greylist"
    logger.info(f"Processing {greylist_path}")
    print(
        generate(
            greylist_path=greylist_path,
            repo1_url="https://repo1.dsop.io",
        )
    )
    greylist_path = "opensource/mattermost/mattermost/mattermost.greylist"
    logger.info(f"Processing {greylist_path}")
    print(
        generate(
            greylist_path=greylist_path,
            repo1_url="https://repo1.dsop.io",
        )
    )
    greylist_path = "atlassian/jira-data-center/jira-node/jira-node.greylist"
    logger.info(f"Processing {greylist_path}")
    print(
        generate(
            greylist_path=greylist_path,
            repo1_url="https://repo1.dsop.io",
        )
    )
