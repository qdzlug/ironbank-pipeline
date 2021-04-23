#!/usr/bin/env python3

import json
import logging
import os
import pathlib
import uuid


class AnchoreAllowlister:
    """
    Anchore Allowlist and Policy generator

    Contains the methods to generate an anchore allowist and mapping for an
    image in the IronBank Pipeline. The allowlist and mapping can both be
    returned in a typical Anchore Policy json.

    """

    def __init__(self):
        self.name = os.environ["IMAGE_NAME"].split("/")[-1]
        self.fullname = os.environ["IMAGE_NAME"].replace("/", "_")
        self.allowlist_id = f"{self.fullname}Allowlist"

    def mapping(self) -> dict:
        return {
            "comment": f"Anchore mapping for the {self.name} image",
            "id": f"{self.fullname}_mapping",
            "image": {"type": "tag", "value": "*"},
            "name": self.name,
            "policy_ids": [
                "default_policy_placeholder",
            ],
            "registry": None,
            "repository": None,
            "whitelist_ids": [self.allowlist_id],
        }

    def allowlist(self, vat_findings) -> dict:
        allowlist = {
            "comment": f"allowlist for {self.name}",
            "id": self.allowlist_id,
            "name": f"allowlist for {self.name}",
            "version": "1_0",
            "items": [],
        }

        allow = set()

        for finding in self.__filter_vat_for_anchore(vat_findings):
            for ac in self.__anchore_scan_findings():
                if (
                    ac["Trigger_Id"]
                    in f"{finding['identifier']}+{finding.get('package')}"
                ):
                    allow.add(
                        (
                            finding["contributor"]["justification"],  # comment
                            ac["Gate"],  # gate
                            str(uuid.uuid4()),  # id
                            ac["Trigger_Id"],  # trigger_id
                        )
                    )

        allowlist["items"] = [
            {
                "comment": a[0],
                "gate": a[1],
                "id": a[2],
                "trigger_id": a[3],
            }
            for a in allow
        ]

        return allowlist

    def policy(self, vat_findings, filename="anchore_allowlist.json") -> dict:
        policy = {
            "blacklisted_images": [],
            "description": f"IronBank Anchore allowlist for the {os.environ['IMAGE_NAME']} image.",
            "id": str(uuid.uuid4()),
            "mappings": [self.mapping()],
            "name": f"{self.name}_ironbank_allowlist",
            "policies": [
                {
                    "comment": "Default Policy Placeholder",
                    "id": "default_policy_placeholder",
                    "name": "DefaultPolicy",
                    "rules": [],
                    "version": "1_0",
                }
            ],
            "version": "1_0",
            "whitelisted_images": [],
            "whitelists": [self.allowlist(vat_findings=vat_findings)],
        }

        logging.debug(json.dumps(policy))
        pathlib.Path(os.environ["ALLOWLISTS"]).mkdir(parents=True, exist_ok=True)
        pathlib.Path(os.environ["ALLOWLISTS"], filename).write_text(json.dumps(policy))

        return policy

    def __filter_vat_for_anchore(self, vat_findings) -> list:
        return [
            finding
            for finding in vat_findings["findings"]
            if finding["findingsState"].lower() in ["approved", "conditional"]
            and finding["source"].lower() in ["anchore_comp", "anchore_cve"]
        ]

    def __anchore_scan_findings(self) -> list:
        """
        Grab the raw anchore compliance json and extract the compliance findings.

        """
        imageid = os.environ["IMAGE_ID"].split(":")[-1]

        anchore_compliance = json.loads(
            pathlib.Path(
                os.environ["ARTIFACT_STORAGE"],
                "scan-results",
                "anchore",
                "anchore_gates.json",
            ).read_text()
        )
        logging.debug(anchore_compliance)

        header = anchore_compliance[imageid]["result"]["header"]
        rows = anchore_compliance[imageid]["result"]["rows"]
        return [dict(zip(header, row)) for row in rows]


def main() -> None:
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

    logging.info("Generating whitelist for Anchore")
    vat_findings = json.loads(
        pathlib.Path(
            os.environ["ARTIFACT_STORAGE"], "lint", "vat_api_findings.json"
        ).read_text()
    )

    logging.debug(vat_findings)

    anchore = AnchoreAllowlister()
    anchore.policy(vat_findings=vat_findings)


if __name__ == "__main__":
    main()
