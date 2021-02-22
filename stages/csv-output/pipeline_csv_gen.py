#!/usr/bin/env python3

import csv
import yaml
import gitlab
import sys
import re
import json
import os
import argparse
import pathlib
import logging
import mysql.connector
from mysql.connector import Error
from bs4 import BeautifulSoup

from scanners import anchore
from scanners.helper import write_csv_from_dict_list

# The InheritableTriggerIds variable contains a list of Anchore compliance trigger_ids
# that are inheritable by child images.
_inheritable_trigger_ids = [
    "639f6f1177735759703e928c14714a59",
    "c2e44319ae5b3b040044d8ae116d1c2f",
    "698044205a9c4a6d48b7937e66a6bf4f",
    "463a9a24225c26f7a5bf3f38908e5cb3",
    "bcd159901fe47efddae5c095b4b0d7fd",
    "320a97c6816565eedf3545833df99dd0",
    "953dfbea1b1e9d5829fbed2e390bd3af",
    "e7573262736ef52353cde3bae2617782",
    "addbb93c22e9b0988b8b40392a4538cb",
    "3456a263793066e9b5063ada6e47917d",
    "3e5fad1c039f3ecfd1dcdc94d2f1f9a0",
    "abb121e9621abdd452f65844954cf1c1",
    "34de21e516c0ca50a96e5386f163f8bf",
    "c4ad80832b361f81df2a31e5b6b09864",
]


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

    parser = argparse.ArgumentParser(
        description="DCCSCR processing of CVE reports from various sources"
    )
    parser.add_argument("--twistlock", help="location of the twistlock JSON scan file")
    parser.add_argument("--oscap", help="location of the oscap scan HTML file")
    parser.add_argument("--oval", help="location of the oval scan HTML file")
    parser.add_argument(
        "--anchore-sec", help="location of the anchore_security.json scan file"
    )
    parser.add_argument(
        "--anchore-gates", help="location of the anchore_gates.json scan file"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        help="directory in which to write CSV output",
        default="./",
    )
    parser.add_argument("--sbom-dir", help="location of the anchore content directory")
    args = parser.parse_args()

    # Create the csv directory if not present
    pathlib.Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    # Get the hardening manifest and additional parameters for _get_complete_whitelist_for_image
    hardening_manifest = _load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Please update your project to contain a hardening_manifest.yaml")
        sys.exit(1)

    image_name = hardening_manifest["name"]
    wl_branch = os.environ.get("WL_TARGET_BRANCH", default="master")

    # get cves and justifications from VAT
    total_whitelist = _get_complete_whitelist_for_image(
        image_name, wl_branch, hardening_manifest
    )

    # Get all justifications
    logging.info("Gathering list of all justifications...")

    j_openscap, j_twistlock, j_anchore = _get_justifications(
        total_whitelist, image_name
    )
    oscap_fail_count = 0
    oval_fail_count = 0
    twist_fail_count = 0
    anchore_num_cves = 0
    anchore_compliance = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(
            args.oscap, j_openscap, csv_dir=args.output_dir
        )
    else:
        generate_blank_oscap_report(csv_dir=args.output_dir)
    if args.oval:
        oval_fail_count = generate_oval_report(args.oval, csv_dir=args.output_dir)
    else:
        generate_blank_oval_report(csv_dir=args.output_dir)
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(
            args.twistlock, j_twistlock, csv_dir=args.output_dir
        )
    if args.anchore_sec:
        anchore_num_cves = anchore.vulnerability_report(
            csv_dir=args.output_dir,
            anchore_security_json=args.anchore_sec,
            justifications=j_anchore,
        )
    if args.anchore_gates:
        anchore_compliance = anchore.compliance_report(
            csv_dir=args.output_dir,
            anchore_gates_json=args.anchore_gates,
            justifications=j_anchore,
        )
    if args.sbom_dir:
        anchore.sbom_report(csv_dir=args.output_dir, sbom_dir=args.sbom_dir)

    generate_summary_report(
        csv_dir=args.output_dir,
        osc=oscap_fail_count,
        ovf=oval_fail_count,
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
    )


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


def _next_ancestor(image_path, whitelist_branch, hardening_manifest=None):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there. Otherwise it will
    default to the old method of using the greylist.

    If neither the hardening_manifest.yaml or the greylist field can be found then there
    is a weird mismatch during migration that needs further inspection.

    """

    # Try to get the parent image out of the local hardening_manifest.
    if hardening_manifest:
        return (
            hardening_manifest["args"]["BASE_IMAGE"],
            hardening_manifest["args"]["BASE_TAG"],
        )

    # Try to load the hardening manifest from a remote repo.
    hm = _load_remote_hardening_manifest(project=image_path)
    if hm is not None:
        return (hm["args"]["BASE_IMAGE"], hm["args"]["BASE_TAG"])

    if os.environ["GREYLIST_BACK_COMPAT"].lower() == "true":
        try:
            greylist = _get_greylist_file_contents(
                image_path=image_path, branch=whitelist_branch
            )
            return (greylist["image_parent_name"], greylist["image_parent_tag"])
        except KeyError as e:
            logging.error("Looks like a hardening_manifest.yaml cannot be found")
            logging.error(
                "Looks like the greylist has been updated to remove fields that should be present in hardening_manifest.yaml"
            )
            logging.error(e)
            sys.exit(1)
    else:
        logging.error(
            "hardening_manifest.yaml does not exist for "
            + image_path
            + ". Please add a hardening_manifest.yaml file to this project"
        )
        logging.error("Exiting.")
        sys.exit(1)


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

    return contents


def _connect_to_db():
    """
    @return mariadb connection for the VAT
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


def _vat_vuln_query(im_name, im_version):
    """
    Gather the vulns for an image as a list of tuples to add to the total_whitelist.
    Collects all findings for the source image layer in VAT

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
                LEFT JOIN container_log cl on c.id = cl.imageid AND cl.id in (SELECT max(id) from container_log group by imageid)
                LEFT JOIN finding_logs fl1 ON fl1.record_type_active = 1 and fl1.record_type = 'state_change' and f.id = fl1.finding_id
                LEFT JOIN finding_logs fl2 ON fl2.record_type_active = 1 and fl2.record_type = 'justification' and f.id = fl2.finding_id
                LEFT JOIN finding_scan_results sr on f.id = sr.finding_id and sr.active = 1
                WHERE c.name=%s and c.version = %s and fl1.in_current_scan = 1 and fl2.in_current_scan = 1;"""
        cursor.execute(query, (im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return result


def _get_vulns_from_query(row):
    """
    For each row in result (returned from VAT db query), create a dictionary gathering
    the necessary items to be compared for each entry in the twistlock, anchore and openscap scans.

    Each row should have 12 items in the form:
    (image_name, image_version, container_status, vuln, source (e.g. anchore_cve), in_current_scan (bool)
    vuln_status (e.g. Approved), approval_comments, justification, description, package, package_path)

    For anchore_comp and anchore_cve, the vuln_description is the package instead of the description.

    example: ('redhat/ubi/ubi8', '8.3', 'Approved', 'CCE-82360-9', 'oscap_comp', 1, 'approved', 'Approved, imported from spreadsheet.',
    'Not applicable. This performs automatic updates to installed packages which does not apply to immutable containers.',
    'Enable dnf-automatic Timer', 'N/A', 'N/A')

    """
    vuln_dict = {}
    vuln_dict["whitelist_source"] = row[0]
    vuln_dict["version"] = row[1]
    vuln_dict["vulnerability"] = row[3]
    vuln_dict["vuln_source"] = row[4]
    vuln_dict["status"] = row[6]
    vuln_dict["justification"] = row[8]
    if row[4] and row[4] == "anchore_cve":
        vuln_dict["vuln_description"] = row[10]
    elif row[4] and row[4] == "anchore_comp" and row[9]:
        vuln_dict["vuln_description"] = row[9].split("\n")[0]
    else:
        vuln_dict["vuln_description"] = row[9]
    return vuln_dict


def _get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of the approved vulnerabilities in VAT associated with w layer.

    """
    total_whitelist = []

    logging.info(f"Grabbing CVEs for: {image_name}")
    # get cves from vat
    if os.environ["IMAGE_NAME"] != os.environ["PROJ_PATH"]:
        logging.error(
            "Name in hardening_manifest does not match GitLab project name (e.g. redhat/ubi/ubi8)"
        )
        logging.error(
            "Quickfix: Edit the name in the hardening_manifest to match the GitLab project name"
        )
        logging.error("Issue is known and solution is in progress.")
        sys.exit(1)
    result = _vat_vuln_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])
    # parse CVEs from VAT query
    # empty list is returned if no entry or no cves. NoneType only returned if error.
    # logging.info(result[0])
    if result is None:
        logging.error("No results from vat. Fatal error.")
        sys.exit(1)
    else:
        for row in result:
            logging.debug(row)
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() in [
                "approved",
                "conditional",
            ]:
                total_whitelist.append(vuln_dict)
                logging.debug(vuln_dict)
            else:
                logging.debug(
                    "There is no approval status present in result or cve not approved"
                )

    logging.debug(
        "Length of total whitelist for source image: " + str(len(total_whitelist))
    )

    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #
    parent_image_name, parent_image_version = _next_ancestor(
        image_path=image_name,
        whitelist_branch=whitelist_branch,
        hardening_manifest=hardening_manifest,
    )

    # get parent cves from VAT
    while parent_image_name:
        logging.info(f"Grabbing CVEs for: {parent_image_name}")

        result = _vat_vuln_query(parent_image_name, parent_image_version)

        for row in result:
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() == "approved":
                total_whitelist.append(vuln_dict)

        parent_image_name, parent_image_version = _next_ancestor(
            image_path=parent_image_name,
            whitelist_branch=whitelist_branch,
        )

    logging.info(f"Found {len(total_whitelist)} total whitelisted CVEs")
    return total_whitelist


def _get_justifications(total_whitelist, sourceImageName):
    """
    Gather all justifications for any approved CVE for anchore, twistlock and openscap.
    Keys are in the form vuln-packagename (anchore_cve), vuln-description (twistlock), or vuln (anchore_comp, openscap).

    Examples:
        CVE-2020-13434-sqlite-libs-3.26.0-11.el8 (anchore key)
        CVE-2020-8285-A malicious server can use... (twistlock key, truncated)
        CCE-82315-3 (openscap key)

    """
    cveOpenscap = {}
    cveTwistlock = {}
    cveAnchore = {}

    # Loop through all the greylist files
    # Getting results from VAT, just loop all findings, check if finding is related to base_images or source image
    # Loop through the findings and create the corresponding dict object based on the vuln_source
    for finding in total_whitelist:
        if "vulnerability" in finding.keys():
            if finding["vuln_description"]:
                cveID = finding["vulnerability"] + "-" + finding["vuln_description"]
            else:
                cveID = finding["vulnerability"]
            openscapID = finding["vulnerability"]
            trigger_id = finding["vulnerability"]
            logging.debug(cveID)
            # Twistlock finding
            if finding["vuln_source"] == "twistlock_cve":
                if finding["whitelist_source"] == sourceImageName:
                    cveTwistlock[cveID] = finding["justification"]
                else:
                    cveTwistlock[cveID] = "Inherited from base image."
                    logging.debug("Twistlock inherited cve")

            # Anchore finding
            elif (
                finding["vuln_source"] == "anchore_cve"
                or finding["vuln_source"] == "anchore_comp"
            ):
                if finding["whitelist_source"] == sourceImageName:
                    cveAnchore[cveID] = finding["justification"]
                    cveAnchore[trigger_id] = finding["justification"]
                else:
                    logging.debug("Anchore inherited cve")
                    cveAnchore[cveID] = "Inherited from base image."
                    if trigger_id in _inheritable_trigger_ids:
                        cveAnchore[trigger_id] = "Inherited from base image."

            # OpenSCAP finding
            elif finding["vuln_source"] == "oscap_comp":
                if finding["whitelist_source"] == sourceImageName:
                    cveOpenscap[openscapID] = finding["justification"]
                else:
                    cveOpenscap[openscapID] = "Inherited from base image."
                    logging.debug("Oscap inherited cve")
    return cveOpenscap, cveTwistlock, cveAnchore


# Blank OSCAP Report
def generate_blank_oscap_report(csv_dir):
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# Blank oval Report
def generate_blank_oval_report(csv_dir):
    oval_report = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", ""]
    )
    oval_report.close()


# SUMMARY REPORT
def generate_summary_report(
    csv_dir, osc, ovf, tlf, anchore_num_cves, anchore_compliance
):
    sum_data = open(csv_dir + "summary.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(sum_data)

    header = ["Scan", "Automated Findings", "Manual Checks", "Total"]

    # if the osc arg type is an int, the scan was skipped so output zero values
    if type(osc) == int:
        osl = ["OpenSCAP - DISA Compliance", 0, 0, 0]
    # osc arg is a tuple, meaning the generate_oscap_report and generate_oval_report functions were run
    else:
        osl = ["OpenSCAP - DISA Compliance", osc[0], osc[1], osc[0] + osc[1]]

    ovf = ["OpenSCAP - OVAL Results", int(ovf or 0), 0, int(ovf or 0)]
    anchore_vulns = ["Anchore CVE Results", anchore_num_cves, 0, anchore_num_cves]
    anchore_comps = [
        "Anchore Compliance Results",
        anchore_compliance["stop_count"],
        0,
        anchore_compliance["stop_count"],
    ]
    twl = ["Twistlock Vulnerability Results", int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(ovf)
    csv_writer.writerow(twl)
    csv_writer.writerow(anchore_vulns)
    csv_writer.writerow(anchore_comps)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + ovf[1] + anchore_vulns[1] + anchore_comps[1] + twl[1],
            osl[2] + ovf[2] + anchore_vulns[2] + anchore_comps[2] + twl[2],
            osl[3] + ovf[3] + anchore_vulns[3] + anchore_comps[3] + twl[3],
        ]
    )

    csv_writer.writerow("")
    # date_str = 'Scans performed on: ' + str(osc[2])
    # csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = f"Scans performed on container layer sha256: {anchore_compliance['image_id']},,,"
    csv_writer.writerow([sha_str])
    sum_data.close()


# Generate csv for OSCAP findings with justifications
def generate_oscap_report(oscap, justifications, csv_dir):
    oscap_cves = get_oscap_full(oscap, justifications)
    oscap_data = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_data)
    count = 0
    fail_count = 0
    nc_count = 0
    scanned = ""
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line["result"] == "fail":
            fail_count += 1
        elif line["result"] == "notchecked":
            nc_count += 1
        scanned = line["scanned_date"]
        try:
            csv_writer.writerow(line.values())
        except Exception as e:
            logging.error(f"problem writing line: {line.values()}")
            raise e
    oscap_data.close()
    return fail_count, nc_count, scanned


# Get full OSCAP report with justifications for csv export
def get_oscap_full(oscap_file, justifications):
    with open(oscap_file, mode="r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text
        id_regex = re.compile(".*rule-detail-.*")
        all = divs.find_all("div", {"class": id_regex})

        cces = []
        for x in all:
            # Assign identifiers to null value otherwise it fails when parsing non-RHEL scan results
            identifiers = None

            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find(
                "td", text="Identifiers and References"
            ).find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            cve_justification = ""
            id = identifiers
            if id in justifications.keys():
                cve_justification = justifications[id]

            ret = {
                "title": title,
                # 'table': table,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
                "Justification": cve_justification,
            }
            cces.append(ret)
        return cces


# Generate oval csv
def generate_oval_report(oval, csv_dir):
    oval_cves = get_oval_full(oval)
    oval_data = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_data)
    count = 0
    fail_count = 0
    for line in oval_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line["result"] == "true":
            fail_count += 1
        csv_writer.writerow(line.values())
    oval_data.close()
    return fail_count


# Get OVAL report for csv export
def get_oval_full(oval_file):
    oscap = open(oval_file, "r", encoding="utf-8")
    soup = BeautifulSoup(oscap, "html.parser")
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad + results_good:
        id = x.find("td")
        result = id.find_next_sibling("td")
        cls = result.find_next_sibling("td")
        y = x.find_all(target="_blank")
        references = set()
        for t in y:
            references.add(t.text)
        title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            ret = {
                "id": id.text,
                "result": result.text,
                "cls": cls.text,
                "ref": ref,
                "title": title.text,
            }
            cves.append(ret)
    return cves


# Get results from Twistlock report for csv export
def generate_twistlock_report(twistlock_cve_json, justifications, csv_dir):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if json_data[0]["vulnerabilities"]:
            for d in json_data[0]["vulnerabilities"]:
                # get associated justification if one exists
                id = ""
                cve_justification = ""
                if d["description"]:
                    id = d["cve"] + "-" + d["description"]
                else:
                    id = d["cve"]
                if id in justifications.keys():
                    cve_justification = justifications[id]
                # else cve_justification is ""
                cves.append(
                    {
                        "id": d["cve"],
                        "cvss": d["cvss"],
                        "desc": d["description"],
                        "link": d["link"],
                        "packageName": d["packageName"],
                        "packageVersion": d["packageVersion"],
                        "severity": d["severity"],
                        "status": d["status"],
                        "vecStr": d["vecStr"],
                        "Justification": cve_justification,
                    }
                )
        else:
            cves = []

    fieldnames = [
        "id",
        "cvss",
        "desc",
        "link",
        "packageName",
        "packageVersion",
        "severity",
        "status",
        "vecStr",
        "Justification",
    ]

    write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="tl.csv", csv_dir=csv_dir
    )

    return len(cves)


if __name__ == "__main__":
    main()  # with if
