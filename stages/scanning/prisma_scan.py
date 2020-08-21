#!/usr/bin/env python3
import json
import requests
import argparse
from requests.auth import HTTPBasicAuth
from time import sleep

# Twistlock API
# https://docs.twistlock.com/docs/latest/api/api_reference.html#registry_get

# Postman
# https://twistlock.spacecamp.ninja/api/v1/registry?name=https://artifactory.spacecamp.ninja/docker/ams/ams-dev-local:latest

MAX_RETRIES = 60

class InvalidTwistlockQuery(Exception): pass
class InvalidTwistlockResponseFormat(Exception): pass
class TwistlockTimeout(Exception): pass
class FailedVulnerability(Exception): pass
class IncorrectUsage(Exception): pass



class Twist():
    """
    Class to add an image to twistlock and retrieve the scan results.

    """

    def __init__(self, registry, username, password, url):
        self.base_url = url
        self.registry = registry
        self.username = username
        self.password = password

    def add_image(self, image, tag):
        # Scan the init image
        r = requests.post(f"{self.base_url}/registry/scan", json = {
            "tag": {
                "registry": self.registry,
                "repo": image,
                "tag": tag,
                "digest": "",
            }
        }, auth = HTTPBasicAuth(self.username, self.password))

        if r.status_code != 200:
            raise InvalidTwistlockQuery("bad post")

        return r

    def query_scan_results(self, imageid):
        r = requests.get(f"{self.base_url}/registry", params = {
                    "imageID": imageid,
                    "limit": "1"
                }, auth = HTTPBasicAuth(self.username, self.password))

        # Bail out if things go south
        if r.status_code != 200:
            raise InvalidTwistlockQuery()

        response = r.json()

        if len(response) == 0:
            return None

        return response

    # It was determined that the version file was not actually being used so it was removed
    # and the version is just printed to console if available and will not cause errors in
    # the pipeline if not.
    def print_version(self):
        print(f"Fetching twistlock version from {self.base_url}/version")
        r = requests.get(f"{self.base_url}/version", auth = HTTPBasicAuth(self.username, self.password))

        if r.status_code != 200:
            print(f"Skipping twistlock version, query responded with {r.status_code}")
        else:
            print(f"Twistlock version {r.text}")
        print("\n")






def twistlock_scan(*, name, tag, username, password, filename, twistlock_api, registry, imageid):
    twist = Twist( registry = registry,
                   username = username,
                   password = password,
                   url = twistlock_api )

    # Capture the console version
    twist.print_version()

    # Scan the image
    print(f"Starting Prisma scan for {imageid}")
    twist.add_image(name, tag)

    done = False
    retries = 0
    while not done:
        print(f"Waiting on Prisma scan [{retries}/{MAX_RETRIES}]...")
        report = twist.query_scan_results(imageid)

        if retries > MAX_RETRIES:
            raise TwistlockTimeout(f"Maximum retries of {MAX_RETRIES} hit while waiting for Twistlock scan to complete")

        if report is None:
            sleep(5)
            retries += 1

        else:
            done = True
            f = open(filename, 'w')
            json.dump(report,f)
            f.close()
            print("Prisma Report completed")



if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'DCCSCR processing of CVE reports from various sources')

    parser.add_argument('--name',      help='Name of the image')
    parser.add_argument('--tag',       help='Image tag')
    parser.add_argument('--username',  help='Twistlock username')
    parser.add_argument('--password',  help='Twistlock password')
    parser.add_argument('--filename',  help='Output file for api response')
    parser.add_argument('--imageid',   help='Image ID for current image')
    parser.add_argument('--registry',  help='Nexus URL')
    parser.add_argument('--api_url',   help='Twistlock URL')
    args = parser.parse_args()

    twistlock_scan( registry     = args.registry,
                    twistlock_api = args.api_url,
                    name          = args.name,
                    tag           = args.tag,
                    username      = args.username,
                    password      = args.password,
                    filename      = args.filename,
                    imageid       = args.imageid )
