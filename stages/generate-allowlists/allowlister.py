#!/usr/bin/env python3

import pathlib
import json
import sys
import os
import logging


# CVE gate is `vulnerabilities`
# comment is justification

_empty_mapping = {
    "comment": "Anchore mapping that matches Wordpress images",
    "id": "wordpress_mapping",
    "image": {"type": "tag", "value": "*"},
    "name": "Wordpress",
    "policy_ids": [
        "DoDDockerfileChecks",
        "DoDEffectiveUserChecks",
        "DoDFileChecks",
        "DoDIstioChecks",
        "DoDSoftwareChecks",
        "DoDTransferProtocolChecks",
    ],
    "registry": "*",
    "repository": "wordpress/*",
    "whitelist_ids": [
        "AnchoreEngineWhitelist",
        "AnchoreEnterpriseWhitelist",
        "CommonSUIDFilesWhitelist",
        "RHELSUIDFilesWhitelist",
    ],
}


_empty_whitelist = {
    "comment": "",
    "id": "empty",
    "items": [{"comment": "", "gate": "", "id": "", "trigger_id": ""}],
    "name": "",
    "version": "1_0",
}


def fetch_anchore_findings():
    """
    Grab the raw anchore compliance json and extract the compliance findings.

    """
    digest = os.environ["IMAGE_PODMAN_SHA"]
    image = os.environ["IMAGE_FULLTAG"]
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

    results = anchore_compliance[0][digest][image][0]["detail"]["result"]["result"]
    header = results[imageid]["result"]["header"]
    rows = results[imageid]["result"]["rows"]
    return [dict(zip(header, row)) for row in rows]


def generate_anchore_allowlist(vat_findings):
    """
    Generate the Anchore allowlist for this specific image. Uses the findings from the VAT API response
    to comb through the Anchore response and build the allowlist.

    """
    anchore_compliance = fetch_anchore_findings()

    name = os.environ["IMAGE_NAME"].split("/")[-1]
    allowlist_id = f"{name}Allowlist"

    mapping = {
        "comment": f"Anchore mapping for the {name} images",
        "id": f"{name}_mapping",
        "image": {"type": "tag", "value": "*"},
        "name": name,
        "policy_ids": [
            "DoDDockerfileChecks",
            "DoDEffectiveUserChecks",
            "DoDFileChecks",
            "DoDIstioChecks",
            "DoDSoftwareChecks",
            "DoDTransferProtocolChecks",
        ],
        "registry": None,
        "repository": None,
        "whitelist_ids": [
            "CommonSUIDFilesWhitelist",
            "RHELSUIDFilesWhitelist",
            allowlist_id,
        ],
    }


    allowlist = {
        "comment": f"allowlist for {name}",
        "id": allowlist_id,
        "name": f"allowlist for {name}",
        "version": "1_0",
        "items": list(),
    }

    stuff = set()

    approved_findings = [v for v in vat_findings["findings"] if v["findingsState"] == "approved"]

    for finding in approved_findings:
        if finding["source"] in ["anchore_comp"]:
            for ac in anchore_compliance:
                if finding["identifier"] == ac["Trigger_Id"]:
                    stuff.add(
                        (
                            finding["contributor"]["justification"],
                            ac["Gate"],
                            ac["Trigger_Id"],
                            ac["Trigger_Id"],
                        )
                    )

        elif finding["source"] in ["anchore_cve"]:
            for ac in anchore_compliance:
                trigger_id = f"{finding['identifier']}+{finding['package']}"
                if ac["Trigger_Id"] in trigger_id:
                    stuff.add(
                        (
                            finding["contributor"]["justification"],
                            ac["Gate"],
                            ac["Trigger_Id"],
                            ac["Trigger_Id"],
                        )
                    )

    allowlist["items"] = [
        {
            "comment": s[0],
            "gate": s[1],
            "id": s[2],
            "trigger_id": s[3],
        } for s in stuff
    ]
    logging.info(json.dumps(allowlist))
    logging.info(json.dumps(mapping))


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

    generate_anchore_allowlist(vat_findings=vat_findings)


if __name__ == "__main__":
    main()
