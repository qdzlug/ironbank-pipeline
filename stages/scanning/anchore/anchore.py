#!/usr/bin/env python3

import os
import re
import sys
import json
import pathlib
import logging
import requests
import subprocess

# requests will attempt to use simplejson to decode its payload if it is present
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

    def __get_anchore_api_json(self, url, payload="", ignore404=False):
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
        except JSONDecodeError:
            raise Exception("Got 200 response but is not valid JSON")

    def __get_parent_sha(self, digest):
        """
        Fetch the ancestry and look for the immediate parent digest

        Use the ignore404 flag when fetching the ancestry from the API to mitigate
        the pipeline failing hard when ancestry is not available.
        """
        ancestry = self.__get_anchore_api_json(
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
        version_json = self.__get_anchore_api_json(url)
        logging.info(
            f"Anchore Enterprise Version: {version_json['service']['version']}"
        )
        filename = pathlib.Path(artifacts_path, "anchore-version.txt")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(version_json["service"]["version"], f)

    def __get_extra_vuln_data(self, vulnerability):
        """
        Grab extra vulnerability data

        """
        url = f"{self.url}/query/vulnerabilities?id={vulnerability['vuln']}"
        logging.info(url)

        extra = dict()
        description = "none"

        resp = self.__get_anchore_api_json(url=url)

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
        parent_digest = self.__get_parent_sha(digest)

        if parent_digest:
            url = f"{self.url}/enterprise/images/{digest}/vuln/all?base_digest={parent_digest}"
        else:
            url = f"{self.url}/enterprise/images/{digest}/vuln/all"

        vuln_dict = self.__get_anchore_api_json(url)
        vuln_dict["imageFullTag"] = image

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

        filename = pathlib.Path(artifacts_path, "anchore_api_security_full.json")
        logging.debug(f"Writing to {filename}")
        with filename.open(mode="w") as f:
            json.dump(vuln_dict, f)

        # Add the extra vuln details
        for i in range(len(vuln_dict["vulnerabilities"])):
            extra = self.__get_extra_vuln_data(vuln_dict["vulnerabilities"][i])
            try:
                vuln_dict["vulnerabilities"][i]["extra"] = extra["vuln_data"]
            except KeyError:
                vuln_dict["vulnerabilities"][i]["extra"] = dict()

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

        # Fetch the immediate parent digest if available
        parent_digest = self.__get_parent_sha(digest)

        if parent_digest:
            url = f"{self.url}/enterprise/images/{digest}/check?tag={image}&detail=true&base_digest={parent_digest}"
        else:
            url = f"{self.url}/enterprise/images/{digest}/check?tag={image}&detail=true"

        body_json = self.__get_anchore_api_json(url)

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
        add_cmd = [
            "anchore-cli",
            "--json",
            "--u",
            self.username,
            "--p",
            self.password,
            "--url",
            self.url,
            "image",
            "add",
            "--noautosubscribe",
        ]

        if pathlib.Path("./Dockerfile").is_file():
            add_cmd += ["--dockerfile", "./Dockerfile"]

        add_cmd.append(image)

        try:
            logging.info(f"{' '.join(add_cmd[0:3])} {' '.join(add_cmd[5:])}")
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
        elif image_add.returncode == 1:
            logging.info(
                f"{image} already exists in Anchore. Pulling current scan data."
            )
            return json.loads(image_add.stdout)["detail"]["digest"]
        else:
            logging.error(image_add.stdout)
            logging.error(image_add.stderr)
            sys.exit(image_add.returncode)

    def image_wait(self, digest):
        """
        Wait for Anchore to scan the image.

        """
        logging.info(f"Waiting for Anchore to scan {digest}")
        wait_cmd = [
            "anchore-cli",
            "--u",
            self.username,
            "--p",
            self.password,
            "--url",
            self.url,
            "image",
            "wait",
            "--interval",
            "30",
            "--timeout",
            os.environ.get("ANCHORE_TIMEOUT", default="2400"),
            digest,
        ]
        try:
            os.environ["PYTHONUNBUFFERED"] = "1"
            logging.info(f"{' '.join(wait_cmd[0:2])} {' '.join(wait_cmd[4:])}")
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

        except subprocess.SubprocessError as e:
            logging.error(e)
            logging.exception("Failed while waiting for Anchore to scan image")
            sys.exit(1)

        # Check return code
        if image_wait.returncode != 0:
            logging.error(image_wait.stdout)
            logging.error(image_wait.stderr)
            sys.exit(image_wait.returncode)

    #
    # Content Fetching to build the SBOM
    #
    def __get_content(self, cmd):
        """
        Use anchore-cli to fetch the content specified

        """
        try:
            logging.info(f"{' '.join(cmd[0:3])} {' '.join(cmd[5:])}")
            image_content = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )
        except subprocess.SubprocessError:
            logging.exception("Could not get content of image")
            sys.exit(1)

        if image_content.returncode != 0:
            logging.error(image_content.stdout)
            logging.error(image_content.stderr)
            sys.exit(image_content.returncode)

        logging.debug(image_content.stdout)

        return json.loads(image_content.stdout)

    def image_content(self, digest, artifacts_path):
        """
        Grab the SBOM from Anchore

        """
        content_cmd = [
            "anchore-cli",
            "--json",
            "--u",
            self.username,
            "--p",
            self.password,
            "--url",
            self.url,
            "image",
            "content",
            digest,
        ]

        pathlib.Path(artifacts_path, "sbom").mkdir(parents=True, exist_ok=True)

        content_types = self.__get_content(cmd=content_cmd)

        for ct in content_types:
            cmd = content_cmd + [ct]
            content = self.__get_content(cmd=cmd)
            logging.debug(content)
            filename = pathlib.Path(artifacts_path, "sbom", f"{ct}.json")
            logging.debug(f"Writing to {filename}")
            with filename.open(mode="w") as f:
                json.dump(content, f)

    def generate_sbom(self, image, artifacts_path, output_format, file_type):
        """
        Grab the SBOM from Anchore

        """
        cmd = ["syft", image, "--scope", "all-layers", "-o", f"output_format"]

        sbom_cyclonedx = pathlib.Path(artifacts_path, f"sbom-{output_format}.{file_type}")
        sbom_cyclonedx.mkdir(parents=True, exist_ok=True)
        with (sbom_cyclonedx / "sbom.xml").open("wb") as f:
            try:
                logging.info(f"{' '.join(cmd[0:3])} {' '.join(cmd[5:])}")
                subprocess.run(
                    cmd,
                    check=True,
                    encoding="utf-8",
                    stderr=sys.stderr,
                    stdout=f,
                )
            except subprocess.SubprocessError:
                logging.exception("Could not generate sbom of image")
                sys.exit(1)
