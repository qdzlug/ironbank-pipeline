#!/usr/bin/env python3

import argparse
import json
import logging
import os
import pathlib
import subprocess
import sys
import yaml
from scanners import oscap
from scanners import anchore
from scanners import twistlock

sys.path.append(os.path.join(os.path.dirname(__file__), "../../modules/"))
from vat_api import VATApi  # noqa


##
#
#   Utilizes the following environment variables
#   - LOGLEVEL
#   - ARTIFACT_STORAGE
#   - WL_TARGET_BRANCH
#   - DISTROLESS
#
##


def _load_local_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    paths = [
        pathlib.Path("hardening_manifest.yaml"),
        # Check for the generated hardening manifest. This method will be deprecated.
        pathlib.Path(artifacts_path, "preflight", "hardening_manifest.yaml"),
    ]

    for path in paths:
        logging.debug(f"Looking for {path}")
        if path.is_file():
            logging.debug(f"Using {path}")
            with path.open("r") as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"Couldn't find {path}")
    return None


def _pipeline_whitelist_compare(image_name, hardening_manifest, lint=False):

    logging.debug("Instantiating VATCheckCves class")
    vat_api = VATApi(
        os.environ["IMAGE_NAME"],
        os.environ["IMAGE_VERSION"],
        os.environ["ARTIFACT_STORAGE"],
        os.environ["VAT_BACKEND_SERVER_ADDRESS"],
    )
    # Don't go any further if just linting
    if lint:
        # get cves from vat
        logging.info(f"Retrieving findings for {os.environ['IMAGE_NAME']}")
        # get container data from vat api
        # generate file from container data
        vat_api.get_vat_container_data()
        vat_api.generate_container_data_file()
        approval_status, approval_text = vat_api.get_container_status()
        _check_container_approval_status(
            approval_status, approval_text, vat_api.container_approved_status_list
        )
        export_hm_variables(hardening_manifest)
        sys.exit(0)

    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    vat_api.get_container_data_from_file()

    # add each finding to its respective scan source whitelist set
    wl_set = vat_api.generate_whitelist_tuple()

    whitelist_length = len(wl_set)
    logging.info(f"Number of whitelisted vulnerabilities: {whitelist_length}")
    if whitelist_length > 0:
        logging.info(f"Whitelisted vulnerabilities: {wl_set}")

    # get the vuln_set from the .json files generated by the scanning stage
    vuln_set, vuln_length = _generate_vuln_set(artifacts_path, vat_api.Finding)
    if vuln_length > 0:
        logging.info(f"{vuln_set}")
    try:
        delta = vuln_set.difference(wl_set)
    except Exception:
        logging.exception("There was an error making the vulnerability delta request.")
        sys.exit(1)

    delta_length = len(delta)

    if delta_length != 0:
        _handle_delta(delta, delta_length)
    else:
        logging.info("ALL VULNERABILITIES WHITELISTED")
        logging.info("Scans are passing 100%")


def _generate_vuln_set(artifacts_path, Finding):
    vuln_set = set()
    #
    # If this is NOT a DISTROLESS scan then OpenSCAP findings will be present
    # and should be factored in.
    #
    if not bool(os.environ.get("DISTROLESS")):
        oscap_file = pathlib.Path(
            artifacts_path, "scan-results", "openscap", "report.html"
        )

        oscap_disa_comp = oscap.get_fails(oscap_file)
        oscap_notchecked = oscap.get_notchecked(oscap_file)
        for o in oscap_notchecked:
            oscap_disa_comp.append(o)

        for o in oscap_disa_comp:
            vuln_set.add(Finding("oscap_comp", o["identifiers"], None, None))

    twistlock_cves = twistlock.get_full()
    for tl in twistlock_cves:
        vuln_set.add(
            Finding(
                "twistlock_cve",
                tl["id"],
                tl["packageName"] + "-" + tl["packageVersion"],
                None,
            )
        )

    anchore_findings = anchore.get_findings()
    for anc in anchore_findings:
        if anc["packagePath"] == "pkgdb":
            anc["packagePath"] = None
        vuln_set.add(
            Finding(
                anc["source"], anc["identifier"], anc["package"], anc["packagePath"]
            )
        )

    vuln_length = len(vuln_set)
    logging.info(f"Vulnerabilities found in scanning stage: {vuln_length}")
    return (vuln_set, vuln_length)


def _handle_delta(delta, delta_length):
    logging.error("NON-WHITELISTED VULNERABILITIES FOUND")
    logging.error(f"Number of non-whitelisted vulnerabilities: {delta_length}")
    logging.error("The following vulnerabilities are not whitelisted:")
    delta = list(delta)
    delta.sort(key=lambda x: (x[0], x[2], x[1]))

    delta.insert(0, delta[0]._fields)
    # hardcoding 4 spaces for proper formatting when the string exceeds 30 chars
    for finding in delta:
        logging.error("".join([f"{i}    ".ljust(30) for i in finding]))

    if (
        os.environ["CI_COMMIT_BRANCH"] == "master"
        and "pipeline-test-project" in os.environ["CI_PROJECT_DIR"]
    ):
        # Check if pipeline-test-project's should be allowed through. Change the exit code
        # so it doesn't fail the pipeline.
        logging.info(
            "pipeline-test-project detected. Allowing the pipeline to continue"
        )
    elif os.environ["CI_COMMIT_BRANCH"] == "master":
        pipeline_repo_dir = os.environ["PIPELINE_REPO_DIR"]
        subprocess.run(
            [f"{pipeline_repo_dir}/stages/check-cves/mattermost-failure-webhook.sh"]
        )
    sys.exit(1)


def _check_container_approval_status(
    approval_status, approval_text, approved_status_list
):

    logging.info("CONTAINER APPROVAL STATUS")
    logging.info(approval_status)
    logging.info("CONTAINER APPROVAL TEXT")
    logging.info(approval_text)

    artifact_dir = os.environ["ARTIFACT_DIR"]

    # all cves for container have container approval at ind 2
    approval_status = approval_status.lower().replace(" ", "_")
    if approval_status not in approved_status_list:
        approval_status = "notapproved"
        logging.warning("IMAGE_APPROVAL_STATUS=notapproved")
        if os.environ["CI_COMMIT_BRANCH"] == "master":
            logging.error(
                "This container is not noted as an approved image in VAT. Unapproved images cannot run on master branch. Failing stage."
            )
            if "pipeline-test-project" not in os.environ["CI_PROJECT_DIR"]:
                sys.exit(1)
            else:
                logging.warning("Continuing because pipeline-test-project")

    if approval_text:
        approval_text = approval_text.rstrip()
    else:
        approval_text = ""
    image_approval = {
        "IMAGE_APPROVAL_STATUS": approval_status,
        "IMAGE_APPROVAL_TEXT": approval_text,
    }

    approval_status_file = pathlib.Path(f"{artifact_dir}/image_approval.json")
    with approval_status_file.open(mode="w") as f:
        json.dump(image_approval, f)


def export_hm_variables(hardening_manifest):
    with open("variables.env", "w") as f:
        f.write(f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\n")
        f.write(f"BASE_TAG={hardening_manifest['args']['BASE_TAG']}")
        logging.debug(
            f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\nBASE_TAG={hardening_manifest['args']['BASE_TAG']}"
        )


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

    # Arguments
    parser = argparse.ArgumentParser(description="Run pipelines arguments")
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Lint flag to run the setup but not the business logic",
    )
    args = parser.parse_args()
    # End arguments

    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #

    hardening_manifest = _load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Your project must contain a hardening_manifest.yaml")
        sys.exit(1)

    image = hardening_manifest["name"]

    _pipeline_whitelist_compare(
        image_name=image,
        hardening_manifest=hardening_manifest,
        lint=args.lint,
    )


if __name__ == "__main__":
    main()
