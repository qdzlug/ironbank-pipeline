import json
import os
import sys
import requests
import logging
import pathlib
import jsonschema
import swagger_to_jsonschema
from collections import namedtuple

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


class VATApi:
    """
    Vunerability Assessment Tracker Api Handler
    Contains methods for accessing container data from VAT's endpoints
    TODO: Add VAT import methods when available
    """

    def __init__(
        self,
        image_name,
        image_version,
        artifact_path,
        server_address,
    ):

        logging.info(f"Initializing {self.__class__}")
        self.__image_name = image_name
        self.__image_version = image_version
        self.__artifact_path = artifact_path
        self.__server_address = server_address
        self.__status_code = None
        # list of finding statuses that denote a finding is approved within VAT
        self.finding_approved_status_list = ["approved", "conditional"]
        self.container_approved_status_list = ["approved", "conditionally_approved"]
        self.vat_container_data = {}
        self.Finding = namedtuple(
            "Finding", ["scan_source", "cve_id", "package", "package_path"]
        )

    def get_vat_container_data(self) -> dict:
        """
        Get container data from the VAT api endpoint
        """
        logging.info("Running query to vat api")
        url = f"{self.__server_address}/p1/container"
        try:
            r = requests.get(
                url,
                params={
                    "name": self.__image_name,
                    "tag": self.__image_version,
                },
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"Could not access VAT API: {url}")
            logging.error(e)
            sys.exit(1)

        self.status_code = r.status_code

        if self.status_code == 200:
            logging.info("Fetched data from vat successfully")
            self.__validate_api_swagger(r.json())
            self.vat_container_data = r.json()
        else:
            self.__handle_api_return_error(r, url)

    def __validate_api_swagger(self, response_json) -> None:
        """
        Validate returned data against swagger spec
        """
        url = f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/p1/swagger"
        r = requests.get(url=url)
        vat_findings_swagger_file = pathlib.Path(
            self.__artifact_path, "lint", "vat_findings.swagger.yaml"
        )
        vat_findings_swagger_file.write_text(r.text)
        try:
            logging.info("Validating the VAT response against schema")
            schema = swagger_to_jsonschema.generate(
                main_model="Container",
                swagger_path=str(vat_findings_swagger_file.as_posix()),
            )
            jsonschema.validate(response_json, schema)
        except Exception as e:
            logging.warning(f"Error validating the VAT schema {e}")
            sys.exit(1)

    def __handle_api_return_error(self, response, url) -> None:
        """
        Handle any api return code that isn't 200
        """
        if self.status_code == 404:
            logging.warning(
                f"{self.__image_name}:{self.__image_version} not found in VAT"
            )
            logging.warning(response.text)

        elif self.status_code == 400:
            logging.warning(f"Bad request: {url}")
            logging.warning(response.text)
            sys.exit(1)

        else:
            logging.warning(f"Unknown response from VAT {self.status_code}")
            logging.warning(response.text)
            logging.error("Failing the pipeline, please contact the administrators")
            sys.exit(1)

    def generate_container_data_file(self, filepath=None) -> None:
        """
        Generate file from container data returned by VAT
        """
        if self.status_code == 200:
            if not filepath:
                filepath = (self.__artifact_path, "lint", "vat_api_container_data.json")
            self.vat_container_data_file = pathlib.Path(*filepath)
            logging.info(self.vat_container_data_file.as_posix())
            try:
                with self.vat_container_data_file.open(mode="w") as f:
                    json.dump(self.vat_container_data, f)
            except Exception:
                logging.warning("Unable to generate findings file")
        else:
            logging.warning(
                "No data returned by VAT api, cannot generate findings file."
            )

    def get_container_data_from_file(self, filepath=None) -> None:
        """
        Get container data from file generated in initial api call
        """
        try:
            if not filepath:
                filepath = (self.__artifact_path, "lint", "vat_api_container_data.json")
            self.vat_container_data_file = pathlib.Path(*filepath)
            with self.vat_container_data_file.open(mode="r") as f:
                self.vat_container_data = json.load(f)
        except Exception:
            logging.warning("Unable to read findings file.")

    def get_container_status(self) -> tuple:
        """
        Get approval status for a given container
        """
        try:
            # containerState won't exist if the container isn't in VAT (i.e. a new container)
            if not self.vat_container_data.get("containerState"):
                return ("", "")
            # approver and comment won't exist if the container hasn't been approved
            elif not self.vat_container_data.get("approver"):
                return (
                    self.vat_container_data["containerState"],
                    "",
                )
            # if both exist, container should be approved and should have a comment
            else:
                return (
                    self.vat_container_data["containerState"],
                    self.vat_container_data["approver"]["comment"],
                )
        except KeyError:
            logging.error(
                "Could not gather approval status. Please contact an administrator."
            )
            return None

    def get_container_findings(self) -> dict:
        """
        Get all findings for a container
        """
        try:
            return self.vat_container_data.get("findings", [])
        except KeyError:
            return []

    def generate_whitelist(self) -> list:
        """
        Return all approved findings for a given container and it's base images
        Return type is a list of dictionaries
        """
        whitelist = []
        for finding in self.vat_container_data["findings"]:
            # if a findings status is in the status list the finding is considered approved in VAT and is added to the whitelist
            if finding["findingsState"].lower() in self.finding_approved_status_list:
                whitelist.append(finding)
        return whitelist

    def generate_whitelist_tuple(self) -> set:
        """
        Return all approved findings for a given container and it's base images. Finding data is relevant to check-cves stage vuln comparison
        Return type is a set of namedtuples
        """
        wl_set = set()
        for finding in self.get_container_findings():
            if finding["findingsState"].lower() in self.finding_approved_status_list:
                wl_set.add(
                    self.Finding(
                        finding["source"],
                        finding["identifier"],
                        finding.get("package"),
                        finding.get("packagePath"),
                    )
                )
        return wl_set

    def generate_whitelist_justifications(self) -> list:
        """
        Return all approved findings for a given container and it's base images. Finding data is relevant to csv-output justification gathering
        Return type is a list of dictionaries
        """
        wl_justifications = []
        for finding in self.get_container_findings():
            if finding["findingsState"].lower() in self.finding_approved_status_list:
                try:
                    wl_justifications.append(
                        {
                            "scan_source": finding["source"],
                            "cve_id": finding["identifier"],
                            "package": finding.get("package"),
                            "package_path": finding.get("packagePath"),
                            "justification": finding["contributor"]["justification"]
                            if not finding["inheritsFrom"]
                            else "Inherited from base image.",
                        }
                    )
                except KeyError:
                    logging.error("VAT finding missing key")
        return wl_justifications

    def __str__(self):
        return f"Class type: {self.__class__}\nImage Name: {self.__image_name}\nImage Version: {self.__image_version}\nVAT api return code: {self.__status_code}\nWhitelist Length: {len(self.whitelist)}"

    def __repr__(self):
        return f"Class type: {self.__class__}\nImage Name: {self.__image_name}\nImage Version: {self.__image_version}\nVAT api return code: {self.__status_code}\nWhitelist Length: {len(self.whitelist)}"
