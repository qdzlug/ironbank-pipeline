#!/usr/bin/env python3
##
#
# Parse out the version from either a manifest or the Jenkinsfile
#
# Test for
#   - download.yaml (switch to manifest.yaml)
#   - download.json (switch to manifest.json)
#   - Jenkinsfile
#
##

import os.path
import re
import sys
import argparse
import yaml
import json
import logging


def parse_jenkins():
    logging.info("Jenkinsfile exists, attempting to extract image version")
    version_regex = r"(?<=version:)[ \t]+((?<![\\])['\"])((?:.(?!(?<![\\])\1))*.?)"

    with open("Jenkinsfile", "r") as jf:
        for line in jf:
            v = re.search(version_regex, line)
            if v is None:
                continue

            # Python re module does not support dynamic length for a look-behind
            # no capture expression so the spaces (that I found at least) so the
            # leading spaces will be captured. Also the beginning quote is used
            # as the back-reference group so it will be captured. Strip the
            # whitespace and remove the beginning quote.
            v = v.group().strip()[1:]

            logging.info(f"Discovered version: {v}")
            return v

    return None


def parse():
    if os.path.isfile("download.yaml"):
        logging.info("download.yaml exists, attempting to extract image version")
        with open("download.yaml", "r") as yf:
            try:
                data = yaml.safe_load(yf, Loader=yaml.FullLoader)
                v = data["version"]
                logging.info(f"Discovered version: {v}")
                return v
            except Exception as e:
                logging.info("Version not found in download.yaml")
    else:
        logging.info("Not found: download.yaml")

    if os.path.isfile("download.json"):
        logging.info("download.json exists, attempting to extract image version")
        with open("download.json", "r") as jf:
            try:
                data = json.load(jf)
                v = data["version"]
                logging.info(f"Discovered version: {v}")
                return v
            except Exception as e:
                logging.info("Version not found in download.json")
    else:
        logging.info("Not found: download.json")

    if os.path.isfile("Jenkinsfile"):
        return parse_jenkins()
    else:
        logging.info("Not found: Jenkinsfile")

    return None


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
    parser = argparse.ArgumentParser(description="Version parser arguments")
    parser.add_argument(
        "--output",
        metavar="output",
        default="get_version.sh",
        type=str,
        help="Output directory to write to",
    )
    args = parser.parse_args()
    version = parse()
    # create regex to check if path traversal is in version
    wl_re = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.\-]*")
    if wl_re.fullmatch(version) == None or version == "" or len(version) > 128:
        logging.error(
            "The format for IMG_VERSION is invalid. Please make sure that the value for your version field has a valid format in your download.yaml file"
        )
        return 1
    if version is None:
        logging.error(
            "Could not parse version out of repo. Please include a version field in your download.yaml file."
        )
        logging.error(
            "Reference this MR on how to update the version field appropriately: https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/merge_requests/30"
        )
        return 1
    else:
        with open(args.output, "w") as artifact:
            artifact.write(f"IMG_VERSION={version}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
