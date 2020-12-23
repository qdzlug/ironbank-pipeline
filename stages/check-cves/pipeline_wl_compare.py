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

import os
import sys
import json
import yaml
import gitlab
import pathlib
import logging
import argparse
import mysql.connector
from mysql.connector import Error

from scanners import oscap
from scanners import anchore
from scanners import twistlock


def _connect_to_db():
    """
    @return mariadb connection
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=os.environ["vat_db_host"],
            database=os.environ["vat_db_database_name"],
            user=os.environ["vat_db_connection_user"],
            passwd=os.environ["vat_db_connection_pass"],
        )
        if conn.is_connected():
            # there are many connections to db so this should be uncommented
            # for troubleshooting
            logging.debug(
                "Connected to the host %s with user %s",
                os.environ["vat_db_host"],
                os.environ["vat_db_connection_user"],
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
        logging.info(
            "Could not load hardening_manifest. Defaulting backwards compatibility."
        )
        logging.warning(
            f"This method will be deprecated soon, please switch {project} to hardening_manifest.yaml"
        )

    except yaml.YAMLError as e:
        logging.error("Could not load the hardening_manifest.yaml")
        logging.error(e)
        sys.exit(1)

    return None


def _pipeline_whitelist_compare(image_name, hardening_manifest, lint=False):

    wl_branch = os.getenv("WL_TARGET_BRANCH", default="master")

    image_whitelist = _get_complete_whitelist_for_image(
        image_name=image_name,
        whitelist_branch=wl_branch,
        hardening_manifest=hardening_manifest,
    )

    wl_set = set()
    # approval status is checked when retrieving image_whitelist
    for image in image_whitelist:
        wl_set.add(image.vulnerability)

    # Don't go any further if just linting
    if lint:
        sys.exit(0)

    logging.info(f"Whitelist Set:{wl_set}")
    logging.info(f"Whitelist Set Length: {len(wl_set)}")

    vuln_set = set()

    #
    # If this is NOT a DISTROLESS scan then OpenSCAP findings will be present
    # and should be factored in.
    #
    if not bool(os.environ.get("DISTROLESS")):
        artifacts_path = os.environ["ARTIFACT_STORAGE"]
        oscap_file = pathlib.Path(
            artifacts_path, "scan-results", "openscap", "report.html"
        )
        oval_file = pathlib.Path(
            artifacts_path, "scan-results", "openscap", "report-cve.html"
        )

        oscap_cves = oscap.get_fails(oscap_file)
        oscap_notchecked = oscap.get_notchecked(oscap_file)
        for o in oscap_notchecked:
            oscap_cves.append(o)

        for o in oscap_cves:
            vuln_set.add(o["identifiers"])

        oval_cves = oscap.get_oval(oval_file)
        for oval in oval_cves:
            vuln_set.add(oval)

    twistlock_cves = twistlock.get_full()
    for tl in twistlock_cves:
        vuln_set.add(tl["id"])

    anchore_cves = anchore.get_full()
    for anc in anchore_cves:
        vuln_set.add(anc["cve"])

    logging.info(f"Vuln Set: {vuln_set}")
    logging.info(f"Vuln Set Length: {len(vuln_set)}")
    try:
        delta = vuln_set.difference(wl_set)
    except Exception as e:
        logging.exception(
            f"There was an error making the vulnerability delta request {e}"
        )
        sys.exit(1)

    if len(delta) != 0:
        logging.warning("NON-WHITELISTED VULNERABILITIES FOUND")
        logging.warning(f"Vuln Set Delta: {delta}")
        logging.warning(f"Vuln Set Delta Length: {len(delta)}")
        logging.error(
            f"Scans are not passing 100%. Vuln Set Delta Length: {len(delta)}"
        )
        sys.exit(1)

    logging.info("ALL VULNERABILITIES WHITELISTED")
    logging.info("Scans are passing 100%")
    sys.exit(0)


def _get_greylist_file_contents(image_path, branch):
    """
    Grab the contents of a greylist file. Takes in the path to the image and
    determines the appropriate greylist.

    """
    greylist_file_path = f"{image_path}/{image_path.split('/')[-1]}.greylist"
    try:
        gl = gitlab.Gitlab(os.environ["REPO1_URL"])
        proj = gl.projects.get("dsop/dccscr-whitelists", lazy=True)
        f = proj.files.get(file_path=greylist_file_path, ref=branch)

    except gitlab.exceptions.GitlabError:
        logging.error(
            f"Whitelist retrieval attempted: {greylist_file_path} on {branch}"
        )
        logging.error(f"Error retrieving whitelist file: {sys.exc_info()[1]}")
        sys.exit(1)

    try:
        contents = json.loads(f.decode())
    except ValueError as e:
        logging.error("Could not load greylist as json")
        logging.error(e)
        sys.exit(1)

    if (
        contents["approval_status"] != "approved"
        and os.environ.get("CI_COMMIT_BRANCH").lower() == "master"
    ):
        logging.error("Unapproved image running on master branch")
        sys.exit(1)

    return contents

def _vat_approval_query(im_name, im_version):
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
                WHEN cl.type = 'Approved' and cl.date_time < FC.maxdate THEN 'Pending'
                ELSE cl.type END as container_approval_status
                FROM container_log cl
                INNER JOIN containers c on c.id = cl.imageid
                INNER JOIN
                (SELECT fa.imageid,
                COUNT(*)
                , MAX(fl.date_time) as maxdate
                FROM findings_approvals fa
                INNER JOIN findings_log fl on fl.approval_id = fa.id AND fl.id in (SELECT max(id) FROM findings_log group by approval_id)
                WHERE fa.imageid = (SELECT id from containers WHERE name=%s AND version=%s)
                AND fa.inherited_id is NULL AND fa.in_current_scan = 1 ) FC
                WHERE c.name=%s AND c.version=%s AND cl.id in (SELECT max(id) from container_log GROUP BY imageid);"""
        cursor.execute(query, (im_name, im_version, im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return result

def _vat_vuln_query(im_name, im_version):
    conn = None
    result = None
    try:
        conn = _connect_to_db()
        cursor = conn.cursor(buffered=True)
        # TODO: add new scan logic
        query = """SELECT c.name as container
            , c.version
            , CASE WHEN cl.type is NULL THEN 'Pending' ELSE cl.type END as container_approval_status
            , f.finding
            , f.scan_source
            , f.in_current_scan
            , CASE fl.type
            WHEN fl.type is NULL THEN 'Pending'
            WHEN fl.date_time > cl.date_time and fl.type = 'Approve' THEN 'Reviewed'
            WHEN cl.date_time is NULL and fl.type = 'Approve' THEN 'Reviewed'
            ELSE fl.type END as finding_status
            FROM findings_approvals f
            INNER JOIN containers c on f.imageid = c.id
            LEFT JOIN findings_log fl on f.id = fl.approval_id
            AND fl.id in (SELECT max(id) from findings_log group by approval_id)
            LEFT JOIN container_log cl on c.id = cl.imageid
            AND cl.id in (SELECT max(id) from container_log GROUP BY imageid)
            WHERE f.inherited_id is NULL
            AND c.name=%s
            AND c.version=%s
            AND f.in_current_scan = 1;"""
        cursor.execute(query, (im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return result


def _get_vulns_from_query(row):
    vuln_dict = {}
    vuln_dict["whitelist_source"] = row[0]
    vuln_dict["vulnerability"] = row[3]
    vuln_dict["vuln_source"] = row[4]
    vuln_dict["status"] = row[6]
    # logging.debug(vuln_dict)
    return vuln_dict


def _next_ancestor(image_path, greylist, hardening_manifest=None):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there. Otherwise it will
    default to the old method of using the greylist.

    If neither the hardening_manifest.yaml or the greylist field can be found then there
    is a weird mismatch during migration that needs further inspection.

    """

    # Try to get the parent image out of the local hardening_manifest.
    if hardening_manifest:
        return hardening_manifest["args"]["BASE_IMAGE"]

    # Try to load the hardening manifest from a remote repo.
    hm = _load_remote_hardening_manifest(project=image_path)
    if hm is not None:
        return hm["args"]["BASE_IMAGE"]

    try:
        return greylist["image_parent_name"]
    except KeyError as e:
        logging.error("Looks like a hardening_manifest.yaml cannot be found")
        logging.error(
            "Looks like the greylist has been updated to remove fields that should be present in hardening_manifest.yaml"
        )
        logging.error(e)
        sys.exit(1)


def _get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of vulnerabilities in the greylist associated with w layer.

    """
    total_whitelist = list()

    # TODO: remove after 30 day hardening_manifest merge cutoff
    greylist = _get_greylist_file_contents(
        image_path=image_name, branch=whitelist_branch
    )
    logging.info(f"Grabbing CVEs for: {image_name}")
    # get cves from vat
    result = _vat_vuln_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])
    logging.debug(result)
    # parse CVEs from VAT query
    # empty list is returned if no entry or no cves. NoneType only returned if error.
    if result is None:
        logging.error("No results from vat. Fatal error.")
        sys.exit(1)
    else:
        for row in result:
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() == "approve":
                total_whitelist.append(Vuln(vuln_dict, image_name))
                logging.debug(vuln_dict)
            else:
                logging.debug("There is no approval status present in result.")

    logging.debug(
        "Length of total whitelist for source image: " + str(len(total_whitelist))
    )
    # get container approval from separate query
    approval_status = _vat_approval_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])
    logging.debug(approval_status)
    # get container approval from first row in result, if record in vat, get from record, else set NotFoundInVat
    if approval_status and approval_status[0]:
        check_container_approval = approval_status[0]
    else:
        check_container_approval = "notapproved"

    logging.debug(check_container_approval)
    with open("variables.env", "w") as f:
        # all cves for container have container approval at ind 2
        if check_container_approval.lower() == "approve":
            f.write(f"IMAGE_APPROVAL_STATUS=approved\n")
            logging.debug(f"IMAGE_APPROVAL_STATUS=approved")
        else:
            f.write(f"IMAGE_APPROVAL_STATUS=notapproved\n")
            logging.debug(f"IMAGE_APPROVAL_STATUS=notapproved")
            pipeline_branch = os.getenv("CI_COMMIT_BRANCH")
            if pipeline_branch == "master":
                logging.error(
                    "This is container is listed as unapproved in the VAT. Unapproved images cannot run on master branch. Failing stage."
                )
                sys.exit(1)
        f.write(f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\n")
        f.write(f"BASE_TAG={hardening_manifest['args']['BASE_TAG']}")
        logging.debug(
            f"BASE_IMAGE={hardening_manifest['args']['BASE_IMAGE']}\nBASE_TAG={hardening_manifest['args']['BASE_TAG']}"
        )
    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #
    parent_image = _next_ancestor(
        image_path=image_name, greylist=greylist, hardening_manifest=hardening_manifest
    )

    # get parent cves from VAT
    while parent_image:
        logging.info(f"Grabbing CVEs for: {parent_image}")
        # TODO: remove this after 30 day hardening_manifest merge cutoff
        greylist = _get_greylist_file_contents(
            image_path=parent_image, branch=whitelist_branch
        )

        # TODO: swap this for hardening manifest after 30 day merge cutoff
        result = _vat_vuln_query(greylist["image_name"], greylist["image_tag"])

        for row in result:
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() == "approve":
                total_whitelist.append(Vuln(vuln_dict, image_name))

        parent_image = _next_ancestor(
            image_path=parent_image,
            greylist=greylist,
        )

    logging.info(f"Found {len(total_whitelist)} total whitelisted CVEs")
    return total_whitelist


# need feedback on adjusting vuln
class Vuln:
    vuln_id = ""  # e.g. CVE-2020-14040
    vuln_source = ""  # e.g. Anchore (vat returns anchore_cve)
    whitelist_source = ""  # IM_NAME
    status = ""  # e.g. Pending, Approved

    def __repr__(self):
        return f"Vuln: {self.vulnerability} - {self.vuln_source} - {self.whitelist_source} - {self.status}"

    def __str__(self):
        return f"Vuln: {self.vulnerability} - {self.vuln_source} - {self.whitelist_source} - {self.status}"

    def __init__(self, v, im_name):
        self.vulnerability = v["vulnerability"]
        self.vuln_source = v["vuln_source"]
        self.status = v["status"]
        self.whitelist_source = im_name


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
    # merged in yet. Fetching the parent greylists must be backwards compatible.
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
