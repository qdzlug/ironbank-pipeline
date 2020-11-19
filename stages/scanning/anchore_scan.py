#!/usr/bin/env python3

import re
import os
import sys
import time
import json
import logging
import pathlib
import requests
import subprocess


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
        logging.debug(f"Fetching {url}")
        try:
            r = requests.get(
                url,
                auth=(self.username, self.password),
                params=payload,
                verify=self.verify,
            )
            body = r.text

            if r.status_code == 200:
                # test that the response is valid JSON
                logging.debug("Got response from Anchore. Testing if valid json")
                try:
                    json.loads(body)
                except json.JSONDecodeError:
                    raise Exception("Got 200 response but is not valid JSON")
            else:
                raise Exception(
                    f"Non-200 response recieved from Anchore {str(r.status_code)} - {r.text}"
                )
        except Exception as err:
            raise err

        logging.debug("Json is valid")
        return json.loads(body)

    def get_version(self):
        """
        Fetch the Anchore version and write it to an artifact.

        """
        logging.info("Getting Anchore version")
        url = f"{self.url}/version"
        version_json = self.__get_anchore_api_json(url)
        filename = os.path.join(self.output, "anchore-version.txt")
        logging.debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(version_json["service"]["version"], f)

    def get_vulns(self, digest):
        """
        Fetch the vulnerability data for the scanned image. Will parse the
        vulnerability response and look for VulnDB records. When a VulnDB record
        is found, the URL points to a pod name which is not publicly accessible
        so it will reach back out to Anchore to gather the correct vulnerability data.

        """
        logging.info("Getting vulnerability results")
        try:
            vuln_dict = self.__get_anchore_api_json(
                f"{self.url}/enterprise/images/by_id/{self.imageid}/vuln/all"
            )

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

            vuln_dict["imageFullTag"] = self.image
            # Create json report called anchore_security.json
            try:
                filename = os.path.join(self.output, "anchore_security.json")
                logging.debug(f"Writing to {filename}")
                with open(filename, "w") as fp:
                    json.dump(vuln_dict, fp)

            except Exception as err:
                raise err

        except Exception as err:
            # if any report fails, raise the error and failstop program
            raise err

    def get_compliance(self, digest):
        """
        Fetch the compliance results for the Anchore policy bundle. Will write
        out the actual API response that contains the results, along with the
        subset of the results that was previously used to parse into the findings
        spreadsheet.

        """
        logging.info("Getting compliance results")
        request_url = f"{self.url}/enterprise/images/by_id/{self.imageid}/check?tag={self.image}&detail=true"
        body_json = self.__get_anchore_api_json(request_url)

        # Save the API response
        filename = os.path.join(self.output, "anchore_api_gates_full.json")
        logging.debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(body_json, f)

        digest = list(body_json[0].keys())[0]
        results = body_json[0][digest][self.image][0]["detail"]["result"]["result"]

        # Grab the subset of data used in anchore_gates.json
        results_dict = dict()
        results_dict[self.imageid] = results[self.imageid]

        filename = os.path.join(self.output, "anchore_gates.json")
        logging.debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(results_dict, f)


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

    image = os.getenv("IMAGE_NAME", default="fail")

    # Add the image to Anchore along with it's Dockerfile. Use the `--force` flag to force
    # a reanalysis of the image on pipeline reruns where the digest has not changed.
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
        logging.exception("Could not add image to Anchore")
        return 1

    logging.info(f"{image} added to Anchore")
    logging.info(image_add.stdout)
    digest = json.loads(image_add.stdout)[0]["imageDigest"]

    # TODO: Pass in timeout
    logging.info(f"Waiting for Anchore to scan {image}")

    try:
        os.environ["PYTHONUNBUFFERED"] = "1"
        wait_cmd = ["anchore-cli", "image", "wait", "--timeout", "60", digest]
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
        logging.exception("Failed while waiting for Anchore to scan image")
        return 1

    logging.info(image_wait.stdout)

    endpoint_url = re.sub(
        "/+$", "", os.getenv("ANCHORE_CLI_URL", default="http://localhost:8228/v1/")
    )

    anchore = Anchore(
        url=endpoint_url,
        username=os.getenv("ANCHORE_CLI_USER", default="admin"),
        password=os.getenv("ANCHORE_CLI_PASS", default="foobar"),
        verify=os.getenv("ANCHORE_VERIFY", default=True),
    )

    anchore.get_vulns(digest)
    anchore.get_compliance(digest)
    anchore.get_version(digest)

    return 0


if __name__ == "__main__":
    sys.exit(main())
