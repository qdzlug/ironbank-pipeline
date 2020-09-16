##
#
#
# Test for
#   - download.yaml (switch to manifest.yaml)
#   - version.txt
#   - Jenkinsfile
#
# Parse into IMG_VERSION
#
##

import os.path
import re
import sys
import argparse
import yaml
import json


def parse_jenkins():
    print("Jenkinsfile exists, attempting to extract image version")
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

            print(f"Discovered version: {v}")
            return v

    return None



def parse():

    if os.path.isfile("download.yaml"):
        print("download.yaml exists, attempting to extract image version")
        with open("download.yaml", "r") as yf:
            try:
                data = yaml.load(yf, Loader=yaml.FullLoader)
                v = data["version"]
                print(f"Discovered version: {v}")
                return v
            except Exception as e:
                print("Version not found in download.yaml")
    else:
        print("Not found: download.yaml")


    if os.path.isfile("download.json"):
        print("download.json exists, attempting to extract image version")
        with open("download.json", "r") as jf:
            try:
                data = json.load(jf)
                v = data["version"]
                print(f"Discovered version: {v}")
                return v
            except Exception as e:
                print("Version not found in download.json")
    else:
        print("Not found: download.json")


    if os.path.isfile("Jenkinsfile"):
        return parse_jenkins()
    else:
        print("Not found: Jenkinsfile")

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
        print("Could not parse version")
    else:
        with open(args.output, "w") as artifact:
            artifact.write(f"IMG_VERSION={version}")



if __name__ == "__main__":
    sys.exit(main())

