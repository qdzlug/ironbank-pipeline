#!/usr/bin/env python3

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import requests

logging.basicConfig(level=os.environ.get("PYTHON_LOG_LEVEL", "INFO"))


# TODO: move this module to the `ironbank/pipelines` dir once anchore/enterprise moves to 3.10
class Anchore:
    """
    Anchore Scanner

    Wrapper for the anchorectl and syft tools
    Both tools must be installed for this module to function correctly
    """

    def __init__(self, url, username, password, verify):
        self.url = url
        self.username = username
        self.password = password
        self.verify = verify

    def _get_anchore_api_json(self, url, payload="", ignore404=False):
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
            if ignore404 and r.status_code == 404:
                logging.warning("No ancestry detected")
                return None
            else:
                raise Exception(
                    f"Non-200 response from Anchore {r.status_code} - {r.text}"
                )

        logging.debug("Got response from Anchore. Testing if valid json")
        try:
            return r.json()
        except requests.JSONDecodeError:
            raise Exception("Got 200 response but is not valid JSON")

    def _get_parent_sha(self, digest):
        """
        Fetch the ancestry and look for the immediate parent digest

        Use the ignore404 flag when fetching the ancestry from the API to mitigate
        the pipeline failing hard when ancestry is not available.
        """
        ancestry = self._get_anchore_api_json(
            f"{self.url}/enterprise/images/{digest}/ancestors",
            ignore404=True,
        )

        if ancestry:
            #
            # Ancestry is sorted by the number of shared layers, so the immediate parent will
            # be the last image in the list.
            #
            return ancestry[-1]["imageDigest"]

        return None

    def get_version(self, artifacts_path):
        """
        Fetch the Anchore version and write it to an artifact.

        """
        logging.info("Getting Anchore version")
        url = f"{self.url}/version"
        version_json = self._get_anchore_api_json(url)
        logging.info(
            f"Anchore Enterprise Version: {version_json['service']['version']}"
        )
        filename = Path(artifacts_path, "anchore-version.txt")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(version_json["service"]["version"], f)

    def _get_extra_vuln_data(self, vulnerability):
        """
        Grab extra vulnerability data

        """
        url = f"{self.url}/query/vulnerabilities?id={vulnerability['vuln']}"
        logging.info(url)

        extra = dict()
        description = "none"

        resp = self._get_anchore_api_json(url=url)

        for vuln in resp["vulnerabilities"]:
            if vuln["description"]:
                description = vuln["description"]

        for vuln in resp["vulnerabilities"]:
            if vuln["namespace"] == vulnerability["feed_group"]:
                if not vuln["description"]:
                    vuln["description"] = description
                del vuln["affected_packages"]
                extra["vuln_data"] = vuln

        return extra

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

        # Fetch the immediate parent digest if available
        parent_digest = self._get_parent_sha(digest)

        if parent_digest:
            url = f"{self.url}/enterprise/images/{digest}/vuln/all?base_digest={parent_digest}"
        else:
            url = f"{self.url}/enterprise/images/{digest}/vuln/all"

        vuln_dict = self._get_anchore_api_json(url)
        vuln_dict["imageFullTag"] = image

        filename = Path(artifacts_path, "anchore_api_security_full.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(vuln_dict, f)

        # Add the extra vuln details
        for i in range(len(vuln_dict["vulnerabilities"])):
            extra = self._get_extra_vuln_data(vuln_dict["vulnerabilities"][i])
            vuln_dict["vulnerabilities"][i]["extra"] = extra.get("vuln_data", {})

        # Create json report called anchore_security.json
        filename = Path(artifacts_path, "anchore_security.json")
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

        # Fetch the immediate parent digest if available
        parent_digest = self._get_parent_sha(digest)

        if parent_digest:
            url = f"{self.url}/enterprise/images/{digest}/check?tag={image}&detail=true&base_digest={parent_digest}"
        else:
            url = f"{self.url}/enterprise/images/{digest}/check?tag={image}&detail=true"

        body_json = self._get_anchore_api_json(url)

        # Save the API response
        filename = Path(artifacts_path, "anchore_api_gates_full.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(body_json, f)

        results = body_json[0][digest][image][0]["detail"]["result"]["result"]
        imageid = body_json[0][digest][image][0]["detail"]["result"]["image_id"]

        # Grab the subset of data used in anchore_gates.json
        results_dict = {}
        results_dict[imageid] = results[imageid]

        filename = Path(artifacts_path, "anchore_gates.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(results_dict, f)

    def image_add(self, image):
        """
        Add the image to Anchore along with it's Dockerfile. Use the `--force` flag to force
        a reanalysis of the image on pipeline reruns where the digest has not changed.

        """
        # shim for deprecated env vars
        os.environ["ANCHORECTL_PASSWORD"] = self.password
        os.environ["ANCHORECTL_URL"] = self.url.replace("/v1/", "")
        os.environ["ANCHORECTL_USERNAME"] = self.username

        # new envvars
        os.environ["ANCHORECTL_UPDATE_CHECK"] = "false"
        os.environ["ANCHORECTL_SKIP_API_VERSION_CHECK"] = "true"
        os.environ["ANCHORECTL_IMAGE_NO_AUTO_SUBSCRIBE"] = "true"
        os.environ["ANCHORECTL_IMAGE_WAIT"] = "true"

        logging.info("sending image to anchore for analysis, please wait..")
        add_cmd = ["anchorectl", "image", "add"]

        if Path("./Dockerfile").is_file():
            os.environ["ANCHORECTL_FORCE"] = "true"
            add_cmd += ["--dockerfile", "./Dockerfile"]

        add_cmd.append(image)

        try:
            logging.info(f"{' '.join(add_cmd)}")
            image_add = subprocess.run(
                add_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )
        except subprocess.SubprocessError:
            logging.exception("Could not add image to Anchore")
            sys.exit(1)

        logging.debug(f"Return Code: {image_add.returncode}")

        if image_add.returncode == 0:
            logging.info(f"{image} added to Anchore")
            logging.info(image_add.stdout)

            return json.loads(image_add.stdout)[0]["imageDigest"]
        else:
            logging.error(image_add.stdout)
            logging.error(image_add.stderr)
            sys.exit(image_add.returncode)
