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



# TODO: add a debug variable inherited from the pipeline to determine logging level
logging.basicConfig(level = logging.INFO, format = "%(levelname)s: %(message)s")



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
                data = yaml.load(yf, Loader=yaml.FullLoader)
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
    parser = argparse.ArgumentParser(description = "Version parser arguments")
    parser.add_argument("--output",
                        metavar = "output",
                        default = "get_version.sh",
                        type = str,
                        help = "Output directory to write to")
    args = parser.parse_args()
    version = parse()

    if version is None:
        logging.error("Could not parse version out of repo. Please include a version field in your download.yaml file.")
        logging.error("Reference this MR on how to update the version field appropriately: https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/merge_requests/30")
        return 1
    else:
        with open(args.output, "w") as artifact:
            artifact.write(f"IMG_VERSION={version}")
        return 0



if __name__ == "__main__":
    sys.exit(main())

