#!/usr/bin/env python3

import re
import sys
import yaml
import json
import pathlib
import logging
import argparse
import requests
import jsonschema

# TODO: Remove this
import pprint

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
    except json.JSONDecodeError as e:
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


def _build_ironbank_yaml(alldata):
    ironbank = dict()
    ironbank_yaml = f"""
apiVersion: v1
name: {alldata["image_name"].split("/")[-1]}
tags:
- "latest"
- "{alldata["version"]}"
args:
  BASE_IMAGE_NAME: "{alldata["image_parent_name"]}"
  BASE_IMAGE_TAG: "{alldata["image_parent_tag"]}"
labels:
  org.opencontainers.image.title: "{alldata["image_name"].split("/")[-1]}"
  org.opencontainers.image.description: "TODO"
  org.opencontainers.image.licenses: "TODO"
  org.opencontainers.image.url: "TODO"
  org.opencontainers.image.vendor: "TODO"
  org.opencontainers.image.version: "{alldata["version"]}"
  io.dsop.ironbank.image.keywords: "TODO"
  io.dsop.ironbank.image.type: "TODO"
  io.dsop.ironbank.product.name: "TODO"
  maintainer: "ironbank@dsop.io"
resources:
{yaml.dump(alldata["resources"])}
# Fill in the following details for the current container owner
maintainers:
- name: "TODO"
  username: "TODO"
  email: "{alldata["container_owner"]}"
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

    with open("../../schema/ironbank.schema.json", "r") as s:
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
            file=f"{greylist_path}",
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

    alldata = _prepare_data(greylist, download, jenkinsfile)
    return _build_ironbank_yaml(alldata)


if __name__ == "__main__":
    print(
        generate(
            greylist_path="anchore/enterprise/enterprise/enterprise.greylist",
            repo1_url="https://repo1.dsop.io",
        )
    )
    print(
        generate(
            greylist_path="redhat/ubi/ubi8/ubi8.greylist",
            repo1_url="https://repo1.dsop.io",
        )
    )
    print(
        generate(
            greylist_path="opensource/mattermost/mattermost/mattermost.greylist",
            repo1_url="https://repo1.dsop.io",
        )
    )
    print(
        generate(
            greylist_path="atlassian/jira-data-center/jira-node/jira-node.greylist",
            repo1_url="https://repo1.dsop.io",
        )
    )
