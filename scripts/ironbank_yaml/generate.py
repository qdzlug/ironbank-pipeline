#!/usr/bin/env python3

import re
import sys
import yaml
import json
import pathlib
import logging
import argparse
import requests

# TODO: Remove this
import pprint

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("ironbank_yaml.generate")


class FileNotFound(Exception):
    pass


def fetch_file(url, file, branch):
    url = f"{url}/-/raw/{branch}/{file}"

    logger.debug(url)

    try:
        r = requests.get(url=url)
    except requests.exceptions.RequestException as e:
        raise e

    if r.status_code == 200:
        return r.text


def parse_jenkins(jenkinsfile):
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


def prepare_data(greylist, download, jenkinsfile=None):
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
        version = parse_jenkins(jenkinsfile)
        if version is not None:
            return_dict.update({"version": version})

    return return_dict


def build_ironbank_yaml(alldata):
    pprint.pprint(alldata)


def generate(greylist_path, repo1_url, group="dsop"):
    project_path = "/".join(greylist_path.split("/")[:-1])

    project_url = f"{repo1_url}/{group}/{project_path}"
    greylist_url = f"{repo1_url}/{group}/dccscr-whitelists"

    try:
        greylist = fetch_file(
            url=greylist_url,
            file=f"{greylist_path}",
            branch="master",
        )
        if greylist is None:
            raise FileNotFound("Did not find greylist")

        download = fetch_file(
            url=project_url, file="download.json", branch="development"
        )

        if download is None:
            download = fetch_file(
                url=project_url, file="download.yaml", branch="development"
            )

        try:
            jenkinsfile = fetch_file(
                url=project_url, file="Jenkinsfile", branch="development"
            )
        except requests.exceptions.RequestException:
            pass

    except FileNotFound as e:
        raise e
    except requests.exceptions.RequestException as e:
        raise e

    alldata = prepare_data(greylist, download, jenkinsfile)
    build_ironbank_yaml(alldata)

    return 0


if __name__ == "__main__":
    generate(
        greylist_path="anchore/enterprise/enterprise/enterprise.greylist",
        repo1_url="https://repo1.dsop.io",
    )
    generate(
        greylist_path="redhat/ubi/ubi8/ubi8.greylist", repo1_url="https://repo1.dsop.io"
    )
