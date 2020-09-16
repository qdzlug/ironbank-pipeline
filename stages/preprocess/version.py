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

def parse():

    if os.path.isfile("download.yaml"):
        print("download.yaml exists, attempting to extract image version")
        print("didn't work")
    else:
        print("download.yaml not found")

    if os.path.isfile("version.txt"):
        print("version.txt exists, attempting to extract image version")
    else:
        print("version.txt not found")

    if os.path.isfile("Jenkinsfile"):
        print("Jenkinsfile exists, attempting to extract image version")
        version_regex = r"(?<=version:)[ \t]+((?<![\\])['\"])((?:.(?!(?<![\\])\1))*.?)\1"

        with open("Jenkinsfile", "r") as jf:
            for line in jf:
                v = re.search(version_regex, line)
                if v is None:
                    continue
                vg = v.group().strip()
                return vg
    else:
        print("Jenkinsfile not found")

print(parse())
