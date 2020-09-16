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

def parse_jenkins():
    print("Jenkinsfile exists, attempting to extract image version")
    version_regex = r"(?<=version:)[ \t]+((?<![\\])['\"])((?:.(?!(?<![\\])\1))*.?)\1"

    with open("Jenkinsfile", "r") as jf:
        for line in jf:
            v = re.search(version_regex, line)
            if v is None:
                continue
            v = v.group().strip()
            # Ensure consistency with quotations
            print(f"Discovered version: {v}")
            return "\"" + v[1:-1] + "\""

    return None



def parse():

    if os.path.isfile("download.yaml"):
        print("download.yaml exists, attempting to extract image version")
    else:
        print("Not found: download.yaml")

    if os.path.isfile("download.json"):
        print("download.json exists, attempting to extract image version")
    else:
        print("Not found: download.json")

    if os.path.isfile("version.txt"):
        print("version.txt exists, attempting to extract image version")
    else:
        print("Not found: version.txt")

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
            artifact.write(version)



if __name__ == "__main__":
    sys.exit(main())

