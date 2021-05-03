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

# add global var for api failures.
# TODO: Remove api_exit_code when converting to using the api instead of the query
api_exit_code = 0

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
        logging.error("Could not load hardening_manifest.")
        sys.exit(1)

    except yaml.YAMLError as e:
        logging.error("Could not load the hardening_manifest.yaml")
        logging.error(e)
        sys.exit(1)

    return None


def _pipeline_whitelist_compare(image_name, hardening_manifest, lint=False):

    wl_branch = os.environ.get("WL_TARGET_BRANCH", default="master")

    # Don't go any further if just linting
    if lint:
        _get_complete_whitelist_for_image(
            image_name=image_name,
            whitelist_branch=wl_branch,
            hardening_manifest=hardening_manifest,
        )
        logging.info(api_exit_code)
        sys.exit(api_exit_code)

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
            artifacts_path, "scan-results", "openscap", "report.html"
        )
        oval_file = pathlib.Path(
            artifacts_path, "scan-results", "openscap", "report-cve.html"
        )

        oscap_disa_comp = oscap.get_fails(oscap_file)
        oscap_notchecked = oscap.get_notchecked(oscap_file)
        for o in oscap_notchecked:
            oscap_disa_comp.append(o)

        for o in oscap_disa_comp:
            vuln_set.add(Finding("oscap_comp", o["identifiers"], None, None))

        oval_cves = oscap.get_oval(oval_file)
        for oval in oval_cves:
            vuln_set.add(Finding("oscap_cve", oval["ref"], oval["pkg"], None))

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
    for image in finding_dictionary:
        # loop through all findings for each image listed in the vat-findings.json file
        for finding in finding_dictionary[image]:
            finding_status = finding["finding_status"].lower()
            # if a findings status is in the status list the finding is considered approved in VAT and is added to the whitelist
            if finding_status in status_list:
                whitelist.add(
                    Finding(
                        finding["scan_source"],
                        finding["finding"],
                        finding["package"],
                        finding["package_path"],
                    )
                )

    return whitelist


def _vat_findings_query(im_name, im_version):
    logging.info("Running query to vat api")
    url = f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/p1/container"
    try:
        r = requests.get(
            url,
            params={
                "name": im_name,
                "tag": im_version,
            },
        )
    except requests.exceptions.RequestException as e:
        logging.warning(f"Could not access VAT API: {url}")
        logging.warning(e)
        return None

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
            return None

        return r.json()

    elif r.status_code == 404:
        logging.warning(f"{im_name}:{im_version} not found in VAT")
        logging.warning(r.text)

    elif r.status_code == 400:
        logging.warning(f"Bad request: {url}")
        logging.warning(r.text)

    else:
        logging.warning(f"Unknown response from VAT {r.status_code}")
        logging.warning(r.text)
        logging.error("Failing the pipeline, please contact the administrators")
        global api_exit_code
        api_exit_code = 3


def _vat_approval_query(im_name, im_version):
    """
    Returns the container approval status which is returned by the query as:
    [(image_name, image_version, container_status)]
    """
    conn = None
    result = None
    try:
        conn = _connect_to_db()
        cursor = conn.cursor(buffered=True)
        # TODO: add new scan logic
        query = """SELECT c.name as container
                , c.version
                , CASE
                WHEN cl.type is NULL THEN 'Pending'
                WHEN cl.type = 'Approved' and UA.unapproved > 0 THEN 'Pending'
                WHEN cl.type = 'Conditionally Approved' and UA.unapproved > 0 THEN 'Pending'
                ELSE cl.type END as container_approval_status,
                cl.text as approval_text
                FROM containers c
                LEFT JOIN container_log cl on c.id = cl.imageid  AND cl.id in (
                        SELECT max(id) from container_log GROUP BY imageid)
                LEFT JOIN (SELECT c.id, FC.count as unapproved from containers c
                LEFT JOIN (SELECT f.container_id as c_id, count(*) as count FROM findings f
                INNER JOIN (SELECT * from finding_logs WHERE record_type_active = 1 and record_type = 'state_change'
                        and in_current_scan = 1 and state not in ('approved', 'conditional') and inherited = 0) fl on f.id = fl.finding_id
                        group by f.container_id) FC on c.id = FC.c_id) UA on c.id = UA.id
            WHERE c.name = %s and c.version = %s;"""
        cursor.execute(
            query,
            (
                im_name,
                im_version,
            ),
        )
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
        sys.exit(1)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    if result and result[0][2]:
        approval_status = result[0][2]
        approval_text = result[0][3]
    else:
        approval_status = "notapproved"
        approval_text = None
    return approval_status, approval_text


def _vat_vuln_query(im_name, im_version):
    """
    Returns non inherited vulnerabilities for a specific container
    """
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


def _next_ancestor(parent_image_path, whitelist_branch):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there.

    If the hardening_manifest.yaml can't be found then there
    is a weird mismatch during migration that needs further inspection.

    """

    # Try to load the hardening manifest from a remote repo.
    hm = _load_remote_hardening_manifest(project=parent_image_path)
    # REMOVE if statement when we are no longer using greylists
    if hm is not None:
        return (hm["name"], hm["tags"][0], hm["args"]["BASE_IMAGE"])
    else:
        logging.error(
            "hardening_manifest.yaml does not exist for "
            + parent_image_path
            + ". Please add a hardening_manifest.yaml file to this project"
        )
        logging.error("Exiting.")
        sys.exit(1)


def _get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of vulnerabilities in the hardening manifest associated with w layer.

    """
    vat_findings = {}

    vat_findings[image_name] = []

    logging.info(f"Grabbing CVEs for: {image_name}")
    # get cves from vat
    logging.info(f"Retrieving findings for {os.environ['IMAGE_NAME']}")

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
    _vat_findings_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])

    approval_status, approval_text = _vat_approval_query(
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
    parent_image_path = hardening_manifest["args"]["BASE_IMAGE"]

    # get parent cves from VAT
    while parent_image_path:
        parent_image_name, parent_image_version, parent_image_path = _next_ancestor(
            parent_image_path=parent_image_path,
            whitelist_branch=whitelist_branch,
        )
        logging.info(f"Grabbing CVEs for: {parent_image_name}")
        # TODO: remove this after 30 day hardening_manifest merge cutof
        # TODO: swap this for hardening manifest after 30 day merge cutoff
        result = _vat_vuln_query(parent_image_name, parent_image_version)
        vat_findings[parent_image_name] = []

        for row in result:
            finding_dict = _get_findings_from_query(row)
            vat_findings[parent_image_name].append(finding_dict)

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
