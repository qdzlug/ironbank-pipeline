#!/usr/bin/env python3

import re
import os
import sys
import json
import logging
import pathlib
import requests
import subprocess

try:
    from simplejson.errors import JSONDecodeError
except ImportError:
    from json.decoder import JSONDecodeError


class Anchore:
    """
    Anchore Scanner

    """

    def __init__(self, url, username, password, verify):
        self.url = url
        self.username = username
        self.password = password
        self.verify = verify

    def __get_anchore_api_json(self, url, payload=""):
        """
        Internal api response fetcher. Will check for a valid return code and
        ensure the response has valid json. Once everything has been validated
        it will return a dictionary of the json.

         payload - request payload for anchore api

        """
        logging.info(f"Fetching {url}")
        try:
            r = requests.get(
                url,
                auth=(self.username, self.password),
                params=payload,
                verify=self.verify,
            )
        except requests.RequestException as e:
            logging.error("Failed to connect with Anchore")
            raise e

        if r.status_code != 200:
            raise Exception(
                f"Non-200 response recieved from Anchore {r.status_code} - {r.text}"
            )

        logging.debug("Got response from Anchore. Testing if valid json")
        try:
            return r.json()
        except JSONDecodeError:
            raise Exception("Got 200 response but is not valid JSON")

    def get_version(self, artifacts_path):
        """
        Fetch the Anchore version and write it to an artifact.

        """
        logging.info("Getting Anchore version")
        url = f"{self.url}/version"
        version_json = self.__get_anchore_api_json(url)
        filename = os.path.join(artifacts_path, "anchore-version.txt")
        logging.debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(version_json["service"]["version"], f)

    #
    # For a multi-ancestor image the ancestry must be walked
    #
    def get_vulns(self, digest, image, artifacts_path):
        """
        Fetch the vulnerability data for the scanned image. Will parse the
        vulnerability response and look for VulnDB records. When a VulnDB record
        is found, the URL points to a pod name which is not publicly accessible
        so it will reach back out to Anchore to gather the correct vulnerability data.

        """
        logging.info("Getting vulnerability results")

        # Fetch the ancestry and look for the immediate parent digest
        ancestry = self.__get_anchore_api_json(
            f"{self.url}/enterprise/images/{digest}/ancestors"
        )

        if ancestry:
            #
            # Ancestry is sorted by the number of shared layers, so the immediate parent will
            # be the last image in the list.
            #
            base_digest = ancestry[-1]["imageDigest"]
            url = f"{self.url}/enterprise/images/{digest}/vuln/all?base_digest={base_digest}"
        else:
            url = f"{self.url}/enterprise/images/{digest}/vuln/all"

        vuln_dict = self.__get_anchore_api_json(url)

        for vulnerability in vuln_dict["vulnerabilities"]:
            # If VulnDB record found, retrive set of reference URLs associated with the record.
            if vulnerability["feed_group"] == "vulndb:vulnerabilities":
                # "http://anchore-anchore-engine-api:8228/v1" or URL to replace may
                #  need to be modified when changes to the Anchore installation occur
                vulndb_request_url = re.sub(
                    "http://([a-z-_0-9:]*)/v1", self.url, vulnerability["url"]
                )
                vulndb_dict = self.__get_anchore_api_json(vulndb_request_url)
                for vulndb_vuln in vulndb_dict["vulnerabilities"]:
                    vulnerability["url"] = vulndb_vuln["references"]

        vuln_dict["imageFullTag"] = image

        # Create json report called anchore_security.json
        filename = pathlib.Path(artifacts_path, "anchore_security.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(vuln_dict, f)

    def get_compliance(self, digest, image, artifacts_path):
        """
        Fetch the compliance results for the Anchore policy bundle. Will write
        out the actual API response that contains the results, along with the
        subset of the results that was previously used to parse into the findings
        spreadsheet.

        """
        logging.info("Getting compliance results")
        request_url = (
            f"{self.url}/enterprise/images/{digest}/check?tag={image}&detail=true"
        )
        body_json = self.__get_anchore_api_json(request_url)

        # Save the API response
        filename = pathlib.Path(artifacts_path, "anchore_api_gates_full.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(body_json, f)

        results = body_json[0][digest][image][0]["detail"]["result"]["result"]
        imageid = body_json[0][digest][image][0]["detail"]["result"]["image_id"]

        # Grab the subset of data used in anchore_gates.json
        results_dict = dict()
        results_dict[imageid] = results[imageid]

        filename = pathlib.Path(artifacts_path, "anchore_gates.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(results_dict, f)

    def image_add(self, image):
        """
        Add the image to Anchore along with it's Dockerfile. Use the `--force` flag to force
        a reanalysis of the image on pipeline reruns where the digest has not changed.

        """
        if pathlib.Path("./Dockerfile").is_file():
            add_cmd = [
                "anchore-cli",
                "--json",
                "image",
                "add",
                "--noautosubscribe",
                "--dockerfile",
                "./Dockerfile",
                "--force",
                image,
            ]
        else:
            add_cmd = [
                "anchore-cli",
                "--json",
                "image",
                "add",
                "--noautosubscribe",
                "--force",
                image,
            ]

        try:
            logging.info(" ".join(add_cmd))
            image_add = subprocess.run(
                add_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                encoding="utf-8",
            )
        except subprocess.SubprocessError as e:
            logging.error(e)
            logging.exception("Could not add image to Anchore")
            sys.exit(1)

        logging.info(f"{image} added to Anchore")
        logging.info(image_add.stdout)

        return json.loads(image_add.stdout)[0]["imageDigest"]

    def image_wait(self, digest):
        logging.info(f"Waiting for Anchore to scan {digest}")
        timeout = os.getenv("ANCHORE_TIMEOUT", default="2400")
        try:
            os.environ["PYTHONUNBUFFERED"] = "1"
            wait_cmd = ["anchore-cli", "image", "wait", "--timeout", timeout, digest]
            logging.info(" ".join(wait_cmd))
            image_wait = subprocess.Popen(
                wait_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
            )

            while image_wait.poll() is None:
                line = image_wait.stdout.readline().strip()
                if line:
                    logging.info(line)
            os.environ["PYTHONUNBUFFERED"] = "0"

            # Check return code
            if image_wait.returncode != 0:
                raise subprocess.SubprocessError(
                    f"returned non-zero exit status {image_wait.returncode}"
                )

        except subprocess.SubprocessError as e:
            logging.error(e)
            logging.exception("Failed while waiting for Anchore to scan image")
            sys.exit(1)

        logging.info(image_wait.stdout)


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

    anchore = Anchore(
        url=os.environ["ANCHORE_SERVER_ADDRESS"],
        username=os.environ["ANCHORE_USERNAME"],
        password=os.environ["ANCHORE_PASSWORD"],
        verify=os.getenv("ANCHORE_VERIFY", default=True),
    )

    artifacts_path = os.getenv("ANCHORE_SCANS", default="/tmp/anchore_scans")

    # Create the directory if it does not exist
    pathlib.Path(artifacts_path).mkdir(parents=True, exist_ok=True)

    try:
        image = f"{os.environ['REGISTRY1_URL']}/ironbank-staging/{os.environ['IM_NAME']}:{os.environ['IMG_VERSION']}-{os.environ['CI_PIPELINE_ID']}"
    except KeyError as e:
        logging.exception("Could not build up full image tag")
        sys.exit(1)

    digest = anchore.image_add(image)
    anchore.image_wait(digest=digest)
    anchore.get_vulns(digest=digest, image=image, artifacts_path=artifacts_path)
    anchore.get_compliance(digest=digest, image=image, artifacts_path=artifacts_path)
    anchore.get_version(artifacts_path=artifacts_path)


if __name__ == "__main__":
    sys.exit(main())
