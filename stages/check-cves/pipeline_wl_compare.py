#!/usr/bin/env python3

##
#
#   Utilizes the following environment variable
#   - LOGLEVEL
#   - ARTIFACT_STORAGE
#   - WL_TARGET_BRANCH
#   - DISTROLESS
#
##

import argparse
from base64 import b64decode
import json
import logging
import os
import pathlib
import subprocess
import sys

import gitlab
import jsonschema
import mysql.connector
from mysql.connector import Error
import requests
import yaml
from collections import namedtuple
from scanners import oscap
from scanners import anchore
from scanners import twistlock
import swagger_to_jsonschema


Finding = namedtuple("Finding", ["scan_source", "cve_id", "package", "package_path"])


def _connect_to_db():
    """
    @return mariadb connection
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=os.environ["VAT_DB_HOST"],
            database=os.environ["VAT_DB_DATABASE_NAME"],
            user=os.environ["VAT_DB_CONNECTION_USER"],
            passwd=os.environ["VAT_DB_CONNECTION_PASS"],
        )
        if conn.is_connected():
            # there are many connections to db so this should be uncommented
            # for troubleshooting
            logging.debug(
                "Connected to the host %s with user %s",
                os.environ["VAT_DB_HOST"],
                os.environ["VAT_DB_CONNECTION_USER"],
            )
        else:
            logging.critical("Failed to connect to DB")
            sys.exit(1)
    except Error as err:
        logging.critical(err)
        if conn is not None and conn.is_connected():
            conn.close()
        sys.exit(1)

    return conn


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


def _load_remote_hardening_manifest(project, branch="master"):
    """
    Load up a hardening_manifest.yaml from a remote repository.

    If the manifest file is not found then None is returned. A warning will print
    to console to communicate which repository does not have a hardening manifest.

    """
    assert branch in ["master", "development"]

    if project == "":
        return None

    logging.debug(f"Attempting to load hardening_manifest from {project}")

    try:
        gl = gitlab.Gitlab(os.environ["REPO1_URL"])
        proj = gl.projects.get(f"dsop/{project}", lazy=True)
        logging.debug(f"Connecting to dsop/{project}")

        hardening_manifest = proj.files.get(
            file_path="hardening_manifest.yaml", ref=branch
        )
        return yaml.safe_load(hardening_manifest.decode())

    except gitlab.exceptions.GitlabError:
        logging.error(f"Could not load hardening_manifest for {project} on {branch}")
        sys.exit(1)

    except yaml.YAMLError as e:
        logging.error("Could not load the hardening_manifest.yaml")
        logging.error(e)
        sys.exit(1)

    return None


def _pipeline_whitelist_compare(image_name, hardening_manifest, lint=False):

    # Don't go any further if just linting
    if lint:
        _get_complete_whitelist_for_image(
            image_name=image_name,
            hardening_manifest=hardening_manifest,
        )
        # exit lint successfully
        sys.exit(0)

    artifacts_path = os.environ["ARTIFACT_STORAGE"]

    vat_findings_file = pathlib.Path(artifacts_path, "lint", "vat_findings.json")
    try:
        with vat_findings_file.open(mode="r") as f:
            vat_findings = json.load(f)
    except Exception:
        logging.exception("Error reading findings file.")
        sys.exit(1)

    # list of finding statuses that denote a finding is approved within VAT
    approval_status_list = ["approved", "conditional"]
    # add each finding to its respective scan source whitelist set
    wl_set = _finding_approval_status_check(vat_findings, approval_status_list)

    whitelist_length = len(wl_set)
    logging.info(f"Number of whitelisted vulnerabilities: {whitelist_length}")
    if whitelist_length > 0:
        logging.info(f"Whitelisted vulnerabilities: {wl_set}")

    vuln_set = set()

    #
    # If this is NOT a DISTROLESS scan then OpenSCAP findings will be present
    # and should be factored in.
    #
    if not bool(os.environ.get("DISTROLESS")):
        oscap_file = pathlib.Path(
            artifacts_path, "scan-results", "openscap", "compliance_output_report.xml"
        )
        # oval_file = pathlib.Path(
        #     artifacts_path, "scan-results", "openscap", "report-cve.html"
        # )

        oscap_disa_comp = oscap.get_oscap_compliance_findings(oscap_file)

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
    if vuln_length > 0:
        logging.info(f"{vuln_set}")
    try:
        delta = vuln_set.difference(wl_set)
    except Exception:
        logging.exception("There was an error making the vulnerability delta request.")
        sys.exit(1)

    delta_length = len(delta)
    exit_code = 0

    if delta_length != 0:
        exit_code = 1
        logging.error("NON-WHITELISTED VULNERABILITIES FOUND")
        logging.error(f"Number of non-whitelisted vulnerabilities: {delta_length}")
        logging.error("The following vulnerabilities are not whitelisted:")
        delta = list(delta)
        delta.sort(key=lambda x: (x[0], x[2], x[1]))

        delta.insert(0, delta[0]._fields)
        # hardcoding 4 spaces for proper formatting when the string exceeds 30 chars
        for finding in delta:
            logging.error("".join([f"{i}    ".ljust(30) for i in finding]))

        if os.environ["CI_COMMIT_BRANCH"] == "master":
            pipeline_repo_dir = os.environ["PIPELINE_REPO_DIR"]
            subprocess.run(
                [f"{pipeline_repo_dir}/stages/check-cves/mattermost-failure-webhook.sh"]
            )

        if "pipeline-test-project" in os.environ["CI_PROJECT_DIR"]:
            # Check if pipeline-test-project's should be allowed through. Change the exit code
            # so it doesn't fail the pipeline.
            logging.info(
                "pipeline-test-project detected. Allowing the pipeline to continue"
            )
            exit_code = 0

    else:
        logging.info("ALL VULNERABILITIES WHITELISTED")
        logging.info("Scans are passing 100%")

    sys.exit(exit_code)


def _finding_approval_status_check(finding_dictionary, status_list):
    whitelist = set()
    _uninheritable_trigger_ids = [
        "41cb7cdf04850e33a11f80c42bf660b3",
        "cbff271f45d32e78dcc1979dbca9c14d",
        "db0e0618d692b953341be18b99a2865a",
    ]
    for image in finding_dictionary:
        # loop through all findings for each image listed in the vat-findings.json file
        for finding in finding_dictionary[image]:
            finding_status = finding["finding_status"].lower()
            # if a findings status is in the status list the finding is considered approved in VAT and is added to the whitelist
            if finding_status in status_list:
                # if the finding is coming from a base layer and the finding isn't actually inherited, don't include it in the whitelist
                if (
                    image != os.environ["IMAGE_NAME"]
                    and finding["finding"] in _uninheritable_trigger_ids
                ):
                    logging.debug(f"Excluding finding {finding['finding']} for {image}")
                    continue
                whitelist.add(
                    Finding(
                        finding["scan_source"],
                        finding["finding"],
                        finding["package"],
                        finding["package_path"],
                    )
                )

    return whitelist


def _get_vat_findings_api(im_name, im_version):
    logging.info("Running query to vat api")
    url = f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/p1/container"
    container_approval = "notapproved"
    container_approval_text = None
    try:
        r = requests.get(
            url,
            params={
                "name": im_name,
                "tag": im_version,
            },
        )
    except requests.exceptions.RequestException:
        logging.exception(f"Could not access VAT API: {url}")
        sys.exit(1)

    if r.status_code == 200:
        logging.info("Fetched data from vat successfully")

        artifact_dir = os.environ["ARTIFACT_DIR"]
        pathlib.Path(artifact_dir, "vat_api_findings.json").write_text(
            data=r.text, encoding="utf-8"
        )

        try:
            logging.info("Validating the VAT response against schema")
            schema = swagger_to_jsonschema.generate(
                main_model="Container",
                swagger_path=f"{os.path.dirname(__file__)}/../../schema/vat_findings.swagger.yaml",
            )
            jsonschema.validate(r.json(), schema)
        except Exception as e:
            logging.warning(f"Error validating the VAT schema {e}")

        data = r.json()
        container_approval = data["containerState"]
        if "approver" in data:
            container_approval_text = data["approver"]["comment"]

    elif r.status_code == 404:
        logging.warning(f"{im_name}:{im_version} not found in VAT")
        logging.warning(r.text)

    elif r.status_code == 400:
        logging.warning(f"Bad request: {url}")
        logging.warning(r.text)
        sys.exit(1)

    else:
        logging.warning(f"Unknown response from VAT {r.status_code}")
        logging.warning(r.text)
        logging.warning(
            "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
        )
        sys.exit(1)
    return container_approval, container_approval_text


def _vat_vuln_query(im_name, im_version):
    """
    Returns non inherited vulnerabilities for a specific container
    """
    logging.info(f"Retrieving findings for {im_name}:{im_version}")
    conn = None
    result = None
    try:
        conn = _connect_to_db()
        cursor = conn.cursor(buffered=True)
        # TODO: add new scan logic
        query = """SELECT c.name as container
                , c.version
                , CASE WHEN cl.type is NULL THEN "Pending" ELSE cl.type END as container_approval_status
                , f.finding
                , f.scan_source
                , fl1.in_current_scan
                , fl1.state as finding_status
                , fl1.record_text as approval_comments
                , fl2.record_text as justification
                , sr.description
                , f.package
                , f.package_path
                FROM findings f
                INNER JOIN containers c on f.container_id = c.id
                INNER JOIN finding_logs fl on active = 1 and in_current_scan = 1 and inherited = 0 and f.id = fl.finding_id
                LEFT JOIN container_log cl on c.id = cl.imageid AND cl.id in (SELECT max(id) from container_log group by imageid)
                LEFT JOIN finding_logs fl1 ON fl1.record_type_active = 1 and fl1.record_type = 'state_change' and f.id = fl1.finding_id
                LEFT JOIN finding_logs fl2 ON fl2.record_type_active = 1 and fl2.record_type = 'justification' and f.id = fl2.finding_id
                LEFT JOIN finding_scan_results sr on f.id = sr.finding_id and sr.active = 1
                WHERE c.name = %s and c.version = %s;"""
        cursor.execute(query, (im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
        sys.exit(1)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return result


def _get_findings_from_query(row):
    finding_dict = {}
    finding_dict["image_name"] = row[0]
    finding_dict["image_version"] = row[1]
    finding_dict["container_approval_status"] = row[2]
    finding_dict["finding"] = row[3]
    finding_dict["scan_source"] = row[4]
    finding_dict["finding_status"] = row[6]
    finding_dict["approval_comments"] = row[7]
    finding_dict["justification"] = row[8]
    finding_dict["scan_result_description"] = row[9]
    finding_dict["package"] = row[10]
    finding_dict["package_path"] = row[11]
    return finding_dict


def _next_ancestor(parent_image_path):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there.

    If the hardening_manifest.yaml can't be found then there
    is a weird mismatch during migration that needs further inspection.

    """

    # load from development if staging base image is used
    branch = "development" if os.environ.get("STAGING_BASE_IMAGE") else "master"
    logging.info(f"Getting {parent_image_path} hardening_manifest.yaml from {branch}")
    # Try to load the hardening manifest from a remote repo.
    hm = _load_remote_hardening_manifest(project=parent_image_path, branch=branch)
    # REMOVE if statement when we are no longer using greylists
    if hm is not None:
        return (hm["args"]["BASE_IMAGE"], hm["args"]["BASE_TAG"])
    else:
        logging.error(
            "hardening_manifest.yaml does not exist for "
            + parent_image_path
            + ". Please add a hardening_manifest.yaml file to this project"
        )
        logging.error("Exiting.")
        sys.exit(1)


def _get_complete_whitelist_for_image(image_name, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of vulnerabilities in the hardening manifest associated with w layer.

    """
    vat_findings = {}

    vat_findings[image_name] = []

    result = _vat_vuln_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])
    # parse CVEs from VAT query
    # empty list is returned if no entry or no cves. NoneType only returned if error.
    if result is None:
        logging.error("No results from vat. Fatal error.")
        sys.exit(1)
    else:
        for row in result:
            finding_dict = _get_findings_from_query(row)
            vat_findings[image_name].append(finding_dict)

    # get container approval from separate query
    approval_status, approval_text = _get_vat_findings_api(
        os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"]
    )

    logging.info("CONTAINER APPROVAL STATUS")
    logging.info(approval_status)
    logging.info("CONTAINER APPROVAL TEXT")
    logging.info(approval_text)

    artifact_dir = os.environ["ARTIFACT_DIR"]

    # all cves for container have container approval at ind 2
    approval_status = approval_status.lower().replace(" ", "_")
    if approval_status not in ["approved", "conditionally_approved"]:
        approval_status = "notapproved"
        logging.warning("IMAGE_APPROVAL_STATUS=notapproved")
        if os.environ["CI_COMMIT_BRANCH"] == "master":
            logging.error(
                "This container is not noted as an approved image in VAT. Unapproved images cannot run on master branch. Failing stage."
            )
            # TODO: Remove?
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

    with open("variables.env", "w") as f:
        f.write(f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\n")
        f.write(f"BASE_TAG={hardening_manifest['args']['BASE_TAG']}")
        logging.debug(
            f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\nBASE_TAG={hardening_manifest['args']['BASE_TAG']}"
        )
    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #
    base_image = hardening_manifest["args"]["BASE_IMAGE"]
    base_tag = hardening_manifest["args"]["BASE_TAG"]
    # never allow STAGING_BASE_IMAGE to be set when running a master branch pipeline
    if (
        os.environ.get("STAGING_BASE_IMAGE")
        and os.environ["CI_COMMIT_BRANCH"] == "master"
    ):
        logging.error("Cannot use STAGING_BASE_IMAGE on master branch")
        sys.exit(1)
    if os.environ.get("STAGING_BASE_IMAGE"):
        auth_file = "staging_pull_auth.json"
        # Grab prod pull docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank-staging"
    else:
        auth_file = "prod_pull_auth.json"
        # Grab staging docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
        pathlib.Path(auth_file).write_text(pull_auth)
        registry = "ironbank"

    # get parent cves from VAT
    while base_image:

        cmd = [
            "skopeo",
            "inspect",
            "--authfile",
            auth_file,
            f"docker://registry1.dso.mil/{registry}/{base_image}:{base_tag}",
        ]
        logging.info(" ".join(cmd))
        # if skopeo inspect fails, because BASE_IMAGE value doesn't match a registry1 container name
        #   fail back to using existing functionality
        try:
            logging.info("Using skopeo to inspect BASE_IMAGE")
            response = subprocess.run(
                args=cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed 'skopeo inspect' of image: registry1.dso.mil/{registry}/{base_image}:{base_tag} "
            )
            logging.error(f"Return code: {e.returncode}")
            sys.exit(1)
        except Exception:
            logging.exception("Unknown failure when attemping to inspect BASE_IMAGE")

        parent_image_name, parent_image_version = _next_ancestor(
            parent_image_path=base_image_repo,
        )
        result = _vat_vuln_query(base_image, base_tag)
        base_image = parent_image_name
        base_tag = parent_image_version
        vat_findings[base_image] = []

        for row in result:
            finding_dict = _get_findings_from_query(row)
            vat_findings[base_image].append(finding_dict)

    logging.info(f"Artifact Directory: {artifact_dir}")
    filename = pathlib.Path(f"{artifact_dir}/vat_findings.json")

    with filename.open(mode="w") as f:
        json.dump(vat_findings, f)


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
