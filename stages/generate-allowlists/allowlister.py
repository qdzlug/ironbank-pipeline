#!/usr/bin/env python3

import json
import logging
import os
import pathlib
import uuid


# CVE gate is `vulnerabilities`
# comment is justification
# _empty_mapping = {
#     "comment": "Anchore mapping that matches Wordpress images",
#     "id": "wordpress_mapping",
#     "image": {"type": "tag", "value": "*"},
#     "name": "Wordpress",
#     "policy_ids": [
#         "DoDDockerfileChecks",
#         "DoDEffectiveUserChecks",
#         "DoDFileChecks",
#         "DoDIstioChecks",
#         "DoDSoftwareChecks",
#         "DoDTransferProtocolChecks",
#     ],
#     "registry": "*",
#     "repository": "wordpress/*",
#     "whitelist_ids": [
#         "AnchoreEngineWhitelist",
#         "AnchoreEnterpriseWhitelist",
#         "CommonSUIDFilesWhitelist",
#         "RHELSUIDFilesWhitelist",
#     ],
# }
#
#
# _empty_whitelist = {
#     "comment": "",
#     "id": "empty",
#     "items": [{"comment": "", "gate": "", "id": "", "trigger_id": ""}],
#     "name": "",
#     "version": "1_0",
# }


def fetch_anchore_findings():
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


def generate_anchore_allowlist(vat_findings):
    """
    Generate the Anchore allowlist for this specific image. Uses the findings from the VAT API response
    to comb through the Anchore response and build the allowlist.

    """
    anchore_compliance = fetch_anchore_findings()

    name = os.environ["IMAGE_NAME"].split("/")[-1]
    fullname = os.environ["IMAGE_NAME"].replace("/", "_")
    allowlist_id = f"{fullname}Allowlist"

    mapping = {
        "comment": f"Anchore mapping for the {name} image",
        "id": f"{fullname}_mapping",
        "image": {"type": "tag", "value": "*"},
        "name": name,
        "policy_ids": [
            "default_policy_placeholder",
        ],
        "registry": None,
        "repository": None,
        "whitelist_ids": [allowlist_id],
    }

    allowlist = {
        "comment": f"allowlist for {name}",
        "id": allowlist_id,
        "name": f"allowlist for {name}",
        "version": "1_0",
        "items": [],
    }

    allow = set()

    approved_findings = [
        v for v in vat_findings["findings"] if v["findingsState"] == "approved"
    ]

    for finding in approved_findings:
        if finding["source"] in ["anchore_comp"]:
            for ac in anchore_compliance:
                if finding["identifier"] == ac["Trigger_Id"]:
                    allow.add(
                        (
                            finding["contributor"]["justification"],  # comment
                            ac["Gate"],  # gate
                            str(uuid.uuid4()),  # id
                            ac["Trigger_Id"],  # trigger_id
                        )
                    )

        elif finding["source"] in ["anchore_cve"]:
            for ac in anchore_compliance:
                trigger_id = f"{finding['identifier']}+{finding['package']}"
                if ac["Trigger_Id"] in trigger_id:
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

    policy = {
        "blacklisted_images": [],
        "description": f"IronBank Anchore allowlist for the {os.environ['IMAGE_NAME']} image.",
        "id": str(uuid.uuid4()),
        "mappings": [mapping],
        "name": f"{name}_ironbank_allowlist",
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
        "whitelists": [allowlist],
    }

    logging.debug(json.dumps(policy))
    pathlib.Path(os.environ["ALLOWLISTS"]).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.environ["ALLOWLISTS"], "anchore_allowlist.json").write_text(
        json.dumps(policy)
    )


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
